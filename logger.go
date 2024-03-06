package csocks

import (
	"log"
	"os"
)

type customLogger struct {
	*log.Logger
	quiet bool
}

func newCustomLogger() *customLogger {
	return &customLogger{
		Logger: log.New(os.Stdout, "[csocks] ", log.LstdFlags),
		quiet:  false,
	}
}

func (cl *customLogger) Println(v ...interface{}) {
	cl.Logger.Println(v...)
}

func (cl *customLogger) Printf(format string, v ...interface{}) {
	cl.Logger.Printf(format, v...)
}

func (cl *customLogger) PrintlnX(v ...interface{}) {
	if !cl.quiet {
		cl.Logger.Println(v...)
	}
}

func (cl *customLogger) PrintfX(format string, v ...interface{}) {
	if !cl.quiet {
		cl.Logger.Printf(format, v...)
	}
}
