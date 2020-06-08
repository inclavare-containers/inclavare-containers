package api

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	green   = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white   = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow  = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red     = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue    = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan    = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset   = string([]byte{27, 91, 48, 109})
)

func (s *ApiServer) middlewareLoggerWithWriter(out io.Writer) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path

		// Process request
		c.Next()

		username := ""
		if username_i, _ := c.Get("username"); username_i != nil {
			username = username_i.(string)
		}

		end := time.Now()

		// latency in seconds
		latency := end.Sub(start)

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		_, level := colorForStatus(statusCode)

		comment := c.Errors.ByType(gin.ErrorTypePrivate).String()

		var access_sys_tag []string
		if ss, ok := c.Get("access-system"); ok {
			access_sys_tag = append(access_sys_tag, ss.(string))
		}
		access_sys_tag_str := strings.Join(access_sys_tag, " ")

		// logtime client_ip server_ip domain level method http_code url response_time user url_query msg
		fmt.Fprintf(out, "%s %s %s %s %s %s %d %s %.3f %s %s %s `%s`\n",
			end.Format("02/Jan/2006:15:04:05"),
			clientIP,
			"", //TODO: fix me, nodeIP
			c.Request.Host,
			level,
			method,
			statusCode,
			path,
			latency.Seconds(),
			username,
			access_sys_tag_str,
			c.Request.URL.Query().Encode(),
			comment,
		)
	}
}

func colorForStatus(code int) (string, string) {
	switch {
	case code >= 200 && code < 300:
		return green, "INFO"
	case code >= 300 && code < 400:
		return white, "INFO"
	case code >= 400 && code < 500:
		return yellow, "WARN"
	default:
		return red, "ERROR"
	}
}

func colorForMethod(method string) string {
	switch method {
	case "GET":
		return blue
	case "POST":
		return cyan
	case "PUT":
		return yellow
	case "DELETE":
		return red
	case "PATCH":
		return green
	case "HEAD":
		return magenta
	case "OPTIONS":
		return white
	default:
		return reset
	}
}
