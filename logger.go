package logger

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// ContextHandler is our base context handler, it will handle all requests
type ContextHandler struct {
	slog.Handler
	ProjectID string
}

// Enabled determines if to log or not log, if it returns true then Handle will log
func (ch ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return ch.Handler.Enabled(ctx, level)
}

// Handle backend for api, this will be used to configure how the logs will be structured
func (ch ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(ch.addRequestID(ctx)...)
	return ch.Handler.Handle(ctx, r)
}

// WithAttrs overriding default implementation otherwise it will call the starting JSON Handler
func (ch ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ContextHandler{ch.Handler.WithAttrs(attrs), ch.ProjectID}
}

// WithGroup overriding default implementation otherwise it will call the starting JSON Handler
func (ch ContextHandler) WithGroup(name string) slog.Handler {
	return ContextHandler{ch.Handler.WithGroup(name), ch.ProjectID}
}

func (ch ContextHandler) addRequestID(ctx context.Context) []slog.Attr {
	var as []slog.Attr
	correlation := getDefaultValueFromContext(ctx, "correlation_id")
	method := getDefaultValueFromContext(ctx, "request_method")
	path := getDefaultValueFromContext(ctx, "request_path")
	agent := getDefaultValueFromContext(ctx, "request_user_agent")

	group := slog.Group("meta_information", slog.String("request_method", method),
		slog.String("request_path", path),
		slog.String("request_user_agent", agent))
	as = append(as, group)

	if strings.Contains(correlation, "/") {
		as = append(as, slog.Any("logging.googleapis.com/trace", fmt.Sprintf("projects/%s/traces/%s", ch.ProjectID, strings.Split(correlation, "/")[0])))
		as = append(as, slog.Any("logging.googleapis.com/spanId", strings.Split(correlation, "/")[1]))
	} else {
		as = append(as, slog.String("logging.googleapis.com/trace", correlation))
	}

	return as
}

// getDefaultValueFromContext get default value from context
func getDefaultValueFromContext(ctx context.Context, key string) string {
	value := ""
	ctxValue := ctx.Value(key)
	if ctxValue != nil {
		value = ctxValue.(string)
	}
	return value
}

// CorrelationID adding correlation id in context
func CorrelationID(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestID := strings.TrimSpace(c.Request().Header.Get("X-Cloud-Trace-Context"))
		if requestID == "" {
			requestID = randomString(32)
		}

		ctx := context.WithValue(c.Request().Context(), "correlation_id", requestID)
		request := c.Request().Clone(ctx)
		c.SetRequest(request)

		return next(c)
	}
}

// AddRouteMetaData adding meta-information about the route. Method, Path, User Agent
func AddRouteMetaData(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		path := c.Request().RequestURI
		method := c.Request().Method
		userAgent := c.Request().UserAgent()

		ctx := context.WithValue(c.Request().Context(), "request_path", path)
		ctx = context.WithValue(ctx, "request_method", method)
		ctx = context.WithValue(ctx, "request_user_agent", userAgent)

		request := c.Request().Clone(ctx)

		c.SetRequest(request)

		return next(c)
	}
}

// Function to generate a random string of a given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Create a byte slice of the required length
	randomBytes := make([]byte, length)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes)
}

func Replacer(groups []string, a slog.Attr) slog.Attr {
	// Rename attribute keys to match Cloud Logging structured log format
	switch a.Key {
	case slog.LevelKey:
		a.Key = "severity"
		// Map slog.Level string values to Cloud Logging LogSeverity
		// https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
		if level := a.Value.Any().(slog.Level); level == slog.LevelWarn {
			a.Value = slog.StringValue("WARNING")
		}
	case slog.TimeKey:
		a.Key = "timestamp"
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

func Errorf(ctx context.Context, format string, args ...interface{}) {
	slog.ErrorContext(ctx, fmt.Sprintf(format, args...))
}

func Infof(ctx context.Context, format string, args ...interface{}) {
	slog.InfoContext(ctx, fmt.Sprintf(format, args...))
}
