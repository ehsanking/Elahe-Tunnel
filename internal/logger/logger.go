package logger

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

var (
	Info  *log.Logger
	Error *log.Logger
)

func init() {
	// Ensure log directory exists
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	logFile, err := os.OpenFile(filepath.Join(logDir, "elahe-tunnel.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	multiInfo := io.MultiWriter(os.Stdout, logFile)
	multiError := io.MultiWriter(os.Stderr, logFile)

	Info = log.New(multiInfo, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(multiError, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}
