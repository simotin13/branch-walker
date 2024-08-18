package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

type LogLevel int

const (
	TRACE LogLevel = iota
	DEBUG
	ERROR
)

const LOG_FILE_NAME = "covme.log"

var logger *log.Logger
var logLevel LogLevel = ERROR
var isOutLogFile = false
var appName = ""
var prefix = ""
func NewLine() {
	fmt.Printf("\n")
}

func ShowErrorMsg(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n")
	format = prefix + format
	fmt.Fprintf(os.Stderr, format, a...)
}

func ShowAppMsg(format string, a ...interface{}) {
	format = prefix + format
	fmt.Printf(format, a...)
}

func Setup(appName string, level LogLevel, isOutFile bool) {
	appName = appName
	prefix = fmt.Sprintf("[%s]  ", appName)
	isOutLogFile = isOutFile
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	logger.SetFlags(log.Ltime | log.Lmicroseconds)
	logLevel = level
	if isOutLogFile {
		logfile, _ := os.OpenFile(LOG_FILE_NAME, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		logWriter := io.MultiWriter(os.Stdout, logfile)
		logger.SetFlags(log.Ldate | log.Ltime)
		logger.SetOutput(logWriter)
	}
}

func TLog(format string, a ...interface{}) {
	if logLevel <= TRACE {
		logger.Printf("[TRACE] "+format, a...)
	}
}

func DLog(format string, a ...interface{}) {
	if logLevel <= DEBUG {
		logger.Printf("[DEBUG] "+format, a...)
	}
}

func ELog(format string, a ...interface{}) {
	if logLevel <= ERROR {
		logger.Printf("[ERROR] "+format, a...)
	}
}
