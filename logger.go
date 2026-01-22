package csocks

import (
	"fmt"
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
	emitToSink(stringsTrimRightNewline(fmt.Sprintln(v...)))
}

func (cl *customLogger) Printf(format string, v ...interface{}) {
	cl.Logger.Printf(format, v...)
	emitToSink(fmt.Sprintf(format, v...))
}

func (cl *customLogger) PrintlnX(v ...interface{}) {
	if !cl.quiet {
		cl.Logger.Println(v...)
		emitToSink(stringsTrimRightNewline(fmt.Sprintln(v...)))
	}
}

func (cl *customLogger) PrintfX(format string, v ...interface{}) {
	if !cl.quiet {
		cl.Logger.Printf(format, v...)
		emitToSink(fmt.Sprintf(format, v...))
	}
}

func stringsTrimRightNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}
