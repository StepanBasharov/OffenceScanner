package logger

type Logger interface {
	Info(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Debug(msg string, fields ...Field)
	Warn(msg string, fields ...Field)

	With(fields ...Field) Logger
}

type Field struct {
	Key   string
	Value any
}
