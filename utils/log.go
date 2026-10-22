package log

import (
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

type LogLevel int

const (
	ERROR LogLevel = iota
	WARNING
	INFO
	DEBUG
)

func ParseLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "ERROR":
		return ERROR, nil
	case "WARNING":
		return WARNING, nil
	case "INFO":
		return INFO, nil
	case "DEBUG":
		return DEBUG, nil
	default:
		return -1, errors.New("Invalid LogLevel")
	}

}

type Logger struct {
	ErrorLogger   log.Logger
	WarningLogger log.Logger
	InfoLogger    log.Logger
	DebugLogger   log.Logger
}

func New(out io.Writer, prefix string, flag int) *Logger {
	if len(prefix) != 0 {
		prefix = prefix + " "
	}
	return &Logger{
		ErrorLogger:   *log.New(out, prefix+"ERROR: ", flag),
		WarningLogger: *log.New(out, prefix+"WARNING: ", flag),
		InfoLogger:    *log.New(out, prefix+"INFO: ", flag),
		DebugLogger:   *log.New(out, prefix+"DEBUG: ", flag),
	}
}

var std = New(os.Stdout, "Bad Bot Blocker", log.LstdFlags|log.Lmsgprefix)

// The level is shared by every middleware instance and read by the background
// refresh goroutine, so it is stored atomically.
var level = int32(INFO)

func SetLevel(newLevel LogLevel) {
	atomic.StoreInt32(&level, int32(newLevel))
}

func enabled(wanted LogLevel) bool {
	return LogLevel(atomic.LoadInt32(&level)) >= wanted
}

func Error(v ...any) {
	if enabled(ERROR) {
		std.ErrorLogger.Println(v...)
	}
}

func Warning(v ...any) {
	if enabled(WARNING) {
		std.WarningLogger.Println(v...)
	}
}

func Info(v ...any) {
	if enabled(INFO) {
		std.InfoLogger.Println(v...)
	}
}

func Debug(v ...any) {
	if enabled(DEBUG) {
		std.DebugLogger.Println(v...)
	}
}

func Errorf(format string, v ...any) {
	if enabled(ERROR) {
		std.ErrorLogger.Printf(format, v...)
	}
}

func Warningf(format string, v ...any) {
	if enabled(WARNING) {
		std.WarningLogger.Printf(format, v...)
	}
}

func Infof(format string, v ...any) {
	if enabled(INFO) {
		std.InfoLogger.Printf(format, v...)
	}
}

func Debugf(format string, v ...any) {
	if enabled(DEBUG) {
		std.DebugLogger.Printf(format, v...)
	}
}
