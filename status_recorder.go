package main

import (
	"net/http"
)

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(p []byte) (int, error) {
	if rec.statusCode == http.StatusNotFound {
		return len(p), nil
	}
	return rec.ResponseWriter.Write(p)
}
