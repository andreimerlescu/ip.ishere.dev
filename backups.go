package main

import (
	"context"
	"database/sql"
	"time"

	"go.uber.org/zap"
)

func scheduleBackups(ctx context.Context, db *sql.DB, databasePath string, connections int) func() {
	return func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				backupPath := *figs.String("backup_path")
				maintenanceMode.Store(1)
				close(hitChan)
				hitWG.Wait()
				if err := db.Close(); err != nil {
					logger.Error("Failed to close DB for backup", zap.Error(err))
				}
				if err := copyFile(databasePath, backupPath); err != nil {
					logger.Error("DB file copy failed", zap.Error(err))
				} else {
					if err := gzipFile(backupPath); err != nil {
						logger.Error("DB backup compression failed", zap.Error(err))
					}
				}
				var err error
				db, err = sql.Open("sqlite3", databasePath+"?_journal_mode=WAL")
				if err != nil {
					logger.Fatal("Failed to reopen DB after backup", zap.Error(err))
				}
				db.SetMaxOpenConns(connections)
				db.SetMaxIdleConns(connections)
				db.SetConnMaxLifetime(time.Duration(connections) * time.Second)
				if _, err = db.Exec(SqlCreateTable); err != nil {
					logger.Fatal("Re-create table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlCreateHitsTable); err != nil {
					logger.Fatal("Re-create hits table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlCreateHitSummaryTable); err != nil {
					logger.Fatal("Re-create summary table failed", zap.Error(err))
				}
				if _, err = db.Exec(SqlIndexes); err != nil {
					logger.Fatal("Re-create indexes failed", zap.Error(err))
				}
				hitChan = make(chan time.Time, 1000)
				hitWG.Add(1)
				go hitConsumer(ctx, db, hitChan)
				maintenanceMode.Store(0)
				logger.Info("DB backup completed", zap.String("path", backupPath+".gz"))
			}
		}
	}
}
