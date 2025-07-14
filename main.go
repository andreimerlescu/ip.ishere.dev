package main

import (
	"context"
	"fmt"
	"github.com/andreimerlescu/figtree/v2"
	"github.com/andreimerlescu/sema"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	renderErr := renderTemplates()
	if renderErr != nil {
		log.Fatal(renderErr)
	}

	figs = figtree.With(figtree.Options{
		ConfigFile:        configFile(),
		IgnoreEnvironment: true,
	})
	figs = configure(figs)
	configErr := figs.Load()
	if configErr != nil {
		log.Fatal(configErr)
	}

	if *figs.Bool(argAbout) {
		about()
		os.Exit(0)
	}

	if *figs.Bool(argVersion) {
		fmt.Println(Version())
		os.Exit(0)
	}

	if strings.HasPrefix(*figs.String(argEnvironment), "prod") {
		logger, _ = zap.NewProduction()
	} else {
		logger, _ = zap.NewDevelopment()
	}
	defer func() {
		ignore(logger.Sync())
	}()

	db := getDatabase(figs)
	hitChan = make(chan time.Time, *figs.Int(argHitBuffer))
	rateLimiter = setupRateLimiter()
	concurrency = sema.New(*figs.Int(argMaxConcurrency))
	httpServer, httpsServer := setupWebServer(mux(figs, db))

	go hitConsumer(ctx, db, hitChan)
	go scheduleUpdateCache(ctx, db)
	go scheduleUpdateSummary(ctx, db)
	if *figs.Bool(argEnableBackups) {
		go scheduleBackups(ctx, db, *figs.String(argDatabase), *figs.Int(argConnections))
	}
	go startHttpsServer(ctx, httpsServer)
	go startHttpServer(ctx, httpServer)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutdown signal received")

	shutdownWebServer(ctx, httpServer, httpsServer)
}
