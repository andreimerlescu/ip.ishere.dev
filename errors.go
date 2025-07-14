package main

import (
	"fmt"
)

func (e ErrRollback) Error() string {
	return fmt.Sprintf("tx.Rollback(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrRollback) Unwrap() error {
	return e.Err
}

func (e ErrQuery) Error() string {
	return fmt.Sprintf("tx.Exec(%s) threw %s", e.Query, e.Err.Error())
}

func (e ErrQuery) Unwrap() error {
	return e.Err
}

func (e ErrDatabase) Error() string {
	return fmt.Sprintf("database %s threw %s", e.Action, e.Err.Error())
}

func (e ErrDatabase) Unwrap() error {
	return e.Err
}

func (e ErrCommit) Error() string {
	return fmt.Sprintf("tx.Commit() threw: %v", e.Err)
}

func (e ErrCommit) Unwrap() error {
	return e.Err
}
