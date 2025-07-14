package main

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"go.uber.org/zap"
)

func hitConsumer(ctx context.Context, db *sql.DB, ch chan time.Time) {
	batchSize := *figs.Int(argHitBatchSize)
	flushInterval := *figs.UnitDuration(argHitFlushInterval)

	var batch []time.Time
	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-ch:
			if !ok {
				if len(batch) > 0 {
					flushBatch(db, batch)
				}
				return
			}
			batch = append(batch, t)
			if len(batch) >= batchSize {
				flushBatch(db, batch)
				batch = batch[:0]
				timer.Reset(flushInterval)
			}
		case <-timer.C:
			if len(batch) > 0 {
				flushBatch(db, batch)
				batch = batch[:0]
			}
			timer.Reset(flushInterval)
		}
	}
}

func flushBatch(db *sql.DB, batch []time.Time) {
	if len(batch) == 0 {
		return
	}

	var placeholders []string
	var args []interface{}

	for _, t := range batch {
		t = t.UTC()
		year, mon, day := t.Date()
		hour, minutes, _ := t.Clock()

		placeholders = append(placeholders, "(?, ?, ?, ?, ?, 1)")
		args = append(args, year, int(mon), day, hour, minutes)
	}

	var builder strings.Builder
	builder.WriteString(SqlFlushBatchBase)
	builder.WriteString(strings.Join(placeholders, ", "))
	builder.WriteString(SqlFlushBatchSecond)
	query := builder.String()

	tx, err := db.Begin()
	if err != nil {
		logger.Error("flushBatch db.Begin error", zap.Error(err))
		return
	}

	_, err = tx.Exec(query, args...)
	if err != nil {
		logger.Error("flushBatch tx.Exec error", zap.Error(err))
		if rbErr := tx.Rollback(); rbErr != nil {
			logger.Error("flushBatch tx.Rollback error", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Error("flushBatch tx.Commit error", zap.Error(err))
	}
}

func updateCache(db *sql.DB) {
	var total int64
	err := db.QueryRow(SqlFindTotalHits).Scan(&total)
	if err != nil {
		logger.Error("updateCache QueryRow error", zap.Error(err))
		return
	}
	totalHitsCache.Store(total)
}

func scheduleUpdateCache(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateCache(db)
		}
	}
}

func updateSummary(db *sql.DB) {
	rows, err := db.Query(SqlQueryFindHitsByYearMonth)
	if err != nil {
		logger.Error("updateSummary QueryRow error", zap.Error(err))
		return
	}
	defer func() {
		ignore(rows.Close())
	}()

	tx, err := db.Begin()
	if err != nil {
		logger.Error("updateSummary db.Begin error", zap.Error(err))
		return
	}

	stmt, err := tx.Prepare(SqlNewHitSummary)
	if err != nil {
		logger.Error("updateSummary tx.Prepare error", zap.Error(err))
		if rbErr := tx.Rollback(); rbErr != nil {
			logger.Error("updateSummary tx.Rollback error", zap.Error(rbErr))
		}
		return
	}
	defer func() {
		ignore(stmt.Close())
	}()

	nowStr := time.Now().UTC().Format(time.RFC3339)

	for rows.Next() {
		var year, month, hits int
		if err := rows.Scan(&year, &month, &hits); err != nil {
			logger.Error("updateSummary rows.Scan error", zap.Error(err))
			continue
		}
		_, err = stmt.Exec(year, month, hits, nowStr)
		if err != nil {
			logger.Error("updateSummary stmt.Exec error", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Error("updateSummary tx.Commit error", zap.Error(err))
	}
}

func scheduleUpdateSummary(ctx context.Context, db *sql.DB) {
	func(ctx context.Context) {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateSummary(db)
			}
		}
	}(ctx)
}
