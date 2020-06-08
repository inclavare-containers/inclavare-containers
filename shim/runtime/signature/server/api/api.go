package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func (s *ApiServer) installRoutes() {
	loggerHandleFunc := s.middlewareLoggerWithWriter(os.Stdout)
	r := s.router
	r.HEAD("/", func(_ *gin.Context) {})
	s.installHealthz()
	{
		g := r.Group("/api/v1/signature")
		g.Use(loggerHandleFunc)
		{
			g.POST("/pkcs1", s.pkcs1Handler)
		}
	}
}

func (s ApiServer) installHealthz() {
	r := s.router
	r.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
}
