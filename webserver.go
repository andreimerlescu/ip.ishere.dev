package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/andreimerlescu/checkfs"
	"github.com/andreimerlescu/checkfs/file"
	"go.uber.org/zap"
)

func setupWebServer(wrappedMux http.Handler) (httpServer *http.Server, httpsServer *http.Server) {
	hasCert, hasKey, isSecure := false, false, false

	certFile := *figs.String(argCert)
	if err := checkfs.File(certFile, file.Options{Exists: true}); err != nil {
		logger.Warn("invalid TLS certificate provided: %v", zap.Error(err))
	} else {
		hasCert = true
	}

	keyFile := *figs.String(argKey)
	if err := checkfs.File(keyFile, file.Options{Exists: true, LessPermissiveThan: 0700}); err != nil {
		logger.Warn("invalid TLS certificate private key provided: %v", zap.Error(err))
	} else {
		hasKey = true
	}

	isSecure = hasCert && hasKey

	httpPort := fmt.Sprintf(":%d", *figs.Int(argPortUnsecure))
	httpsPort := fmt.Sprintf(":%d", *figs.Int(argPortSecure))

	if strings.EqualFold(httpPort, ":") || (isSecure && strings.EqualFold(httpsPort, ":")) {
		logger.Fatal(fmt.Sprintf("invalid http %s https %s provided", httpPort, httpsPort))
	}

	var httpHandler, httpsHandler http.Handler

	if isSecure {
		httpHandler = http.HandlerFunc(redirectToHTTPS)
		httpsHandler = wrappedMux
	} else {
		httpHandler = wrappedMux
		httpsHandler = wrappedMux
	}

	if isSecure {
		httpsServer = &http.Server{
			Addr:    httpsPort,
			Handler: httpsHandler,
		}
	}

	httpServer = &http.Server{
		Addr:    httpPort,
		Handler: httpHandler,
	}
	return
}

func shutdownWebServer(ctx context.Context, httpServer, httpsServer *http.Server) {
	if httpServer != nil && httpsServer != nil {
		close(hitChan)
	}

	ctx2, cancel2 := context.WithTimeout(ctx, *figs.UnitDuration(argShutdownTimeout))
	defer cancel2()

	if httpServer != nil {
		if err := httpServer.Shutdown(ctx2); err != nil {
			logger.Error("HTTP shutdown error: %v", zap.Error(err))
		}
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx2); err != nil {
			logger.Error("HTTPS shutdown error: %v", zap.Error(err))
		}
	}

	logger.Info("Shutdown complete")
}

func startHttpsServer(ctx context.Context, httpsServer *http.Server) {
	go func() {
		<-ctx.Done()
		shutdownWebServer(ctx, nil, httpsServer)
	}()
	log.Printf("Starting HTTPS server on :%d", *figs.Int(argPortSecure))
	err := httpsServer.ListenAndServeTLS(*figs.String(argCert), *figs.String(argKey))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("HTTPS server error: %v", err)
	}
}

func startHttpServer(ctx context.Context, httpServer *http.Server) {
	go func() {
		<-ctx.Done()
		shutdownWebServer(ctx, httpServer, nil)
	}()
	log.Printf("Starting HTTP server on :%d", *figs.Int(argPortUnsecure))
	err := httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server error: %v", zap.Error(err))
	}
}
