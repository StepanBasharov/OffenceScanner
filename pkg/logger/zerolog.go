package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ZeroLogger struct {
	logger zerolog.Logger
}

func NewZeroLogger() Logger {
	zlogger := log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2006-01-02 15:04:05",
		NoColor:    false,
	})
	return &ZeroLogger{logger: zlogger}
}

func (l *ZeroLogger) Info(msg string, fields ...Field) {
	l.logger.Info().Fields(convertFields(fields)).Msg(msg)
}

func (l *ZeroLogger) Error(msg string, fields ...Field) {
	l.logger.Error().Fields(convertFields(fields)).Msg(msg)
}

func (l *ZeroLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug().Fields(convertFields(fields)).Msg(msg)
}

func (l *ZeroLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn().Fields(convertFields(fields)).Msg(msg)
}

func (l *ZeroLogger) With(fields ...Field) Logger {
	return &ZeroLogger{
		logger: l.logger.With().Fields(convertFields(fields)).Logger(),
	}
}

func convertFields(fields []Field) map[string]interface{} {
	result := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		result[f.Key] = f.Value
	}
	return result
}
