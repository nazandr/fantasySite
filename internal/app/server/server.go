package server

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type Server struct {
	config *Config
	logger *logrus.Logger
	router *mux.Router
}

func New(config *Config) *Server {
	s := &Server{
		config: config,
		logger: logrus.New(),
		router: mux.NewRouter(),
	}

	s.configureRouter()

	return s
}

func (s *Server) Start() error {
	if err := s.configureLogger(); err != nil {
		return err
	}

	return http.ListenAndServe(s.config.IP_addr, s.router)
}

func (s *Server) configureLogger() error {
	lvl, err := logrus.ParseLevel(s.config.Log_lvl)
	if err != nil {
		return err
	}

	s.logger.SetLevel(lvl)

	return nil
}
