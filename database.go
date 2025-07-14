package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/andreimerlescu/figtree/v2"
	"go.uber.org/zap"
)

func getDatabase(figs figtree.Plant) *sql.DB {
	databasePath := *figs.String(argDatabase)
	connections := *figs.Int(argConnections)

	db, err := sql.Open("sqlite3", databasePath+"?_journal_mode=WAL")
	if err != nil {
		logger.Fatal(fmt.Sprintf("sql.Open(%s) failed with err", databasePath), zap.Error(err))
	}
	defer func(db *sql.DB) {
		ignore(db.Close())
	}(db)

	db.SetMaxOpenConns(connections)
	db.SetMaxIdleConns(connections)
	db.SetConnMaxLifetime(time.Duration(connections) * time.Second)

	msg := "db.Exec err: "

	_, err = db.Exec(SqlCreateTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlCreateHitsTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlCreateHitSummaryTable)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}

	_, err = db.Exec(SqlIndexes)
	if err != nil {
		logger.Fatal(msg, zap.Error(err))
	}
	return db
}

func updateRequestTracking(db *sql.DB, ipv4, ipv6 string) (IPData, error) {
	data := IPData{IPv4: ipv4, IPv6: ipv6}
	ip := ipv4
	if ip == "" {
		ip = ipv6
	}
	if ip == "" {
		return data, nil
	}

	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		ip = parsedIP.String()
	}

	tx, err := db.Begin()
	if err != nil {
		return data, ErrDatabase{"db.Begin()", err}
	}

	var count int
	var lastVisit string
	err = tx.QueryRow(SqlFindLatest, ip).Scan(&count, &lastVisit)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.Exec(SqlNewRow, ip, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			errRollback := tx.Rollback()
			if errRollback != nil {
				return data, ErrRollback{SqlNewRow, errRollback}
			}
			return data, ErrQuery{SqlNewRow, err}
		}
		data.VisitCount = 1
		data.LastVisit = time.Now().UTC().Format(time.RFC3339)
	} else if err == nil {
		count++
		_, err = tx.Exec(SqlUpdateRow, count, time.Now().UTC().Format(time.RFC3339), ip)
		if err != nil {
			errRollback := tx.Rollback()
			if errRollback != nil {
				return data, ErrRollback{SqlUpdateRow, errRollback}
			}
			return data, ErrQuery{SqlUpdateRow, err}
		}
		data.VisitCount = count
		data.LastVisit = lastVisit
	} else {
		errRollback := tx.Rollback()
		if errRollback != nil {
			return data, ErrRollback{SqlFindLatest, errRollback}
		}
		return data, ErrQuery{SqlFindLatest, err}
	}

	errCommit := tx.Commit()
	if errCommit != nil {
		return data, ErrCommit{err}
	}
	return data, nil
}
