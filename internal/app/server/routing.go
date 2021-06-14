package server

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nazand/fantacySite/internal/app/models"
	"github.com/sirupsen/logrus"
)

const (
	cxtKeyRequestId cxtKey = iota
)

type cxtKey int

type Token struct {
	AcssesToken  string `json:"acsses_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) configureRouter() {
	fs := http.FileServer(http.Dir("/Users/andrey/projects/fantacySite/web/assets"))

	s.router.Use(s.setRequestId)
	s.router.Use(s.loggerReq)
	s.router.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", fs))
	s.router.HandleFunc("/", s.indexHandler()).Methods("GET")
	s.router.HandleFunc("/collection", s.collection()).Methods("GET")
	s.router.HandleFunc("/singup", s.singUp()).Methods("POST")
	s.router.HandleFunc("/singin", s.singIn()).Methods("POST")
}

func (s *Server) setRequestId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), cxtKeyRequestId, id)))
	})
}

func (s *Server) loggerReq(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(cxtKeyRequestId),
		})

		logger.Infof("started %s %s", r.Method, r.RequestURI)
		start := time.Now()

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Infof("completed with %d %s at %v",
			rw.code, http.StatusText(rw.code),
			time.Since(start))
	})
}

func (s *Server) indexHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tpl := template.Must(template.ParseFiles(
			"web/index.html",
			// "web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			Auth  bool
		}{
			Title: "Dota 2 Fantacy",
			CSS:   "/assets/index.css",
			Auth:  false,
		}
		a, _ := s.verify(rw, r)

		data.Auth = a
		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) collection() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tpl := template.Must(template.ParseFiles(
			"web/collection.html",
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			Auth  bool
			Cards []models.PlayerCard
		}{
			Title: "Dota 2 Fantacy",
			CSS:   "/assets/collection.css",
			Auth:  true,
		}
		a, token := s.verify(rw, r)

		if !a {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
		}

		res, err := s.request("http://localhost:8080/auth/collection", "GET", token)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/", http.StatusNotModified)
			return
		}
		defer res.Body.Close()
		cards := &[]models.PlayerCard{}
		if err := json.NewDecoder(res.Body).Decode(cards); err != nil {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			s.logger.Info(err)
			return
		}
		data.Cards = *cards

		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) singUp() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		req := request{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		res, err := s.request("http://localhost:8080/singup", "POST", req)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/", http.StatusNotModified)
			return
		}
		defer res.Body.Close()
		token := &Token{}
		if err := json.NewDecoder(res.Body).Decode(token); err != nil {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			s.logger.Info(err)
			return
		}

		cookie := http.Cookie{
			Name:  "acsses_token",
			Value: token.AcssesToken,
		}
		http.SetCookie(rw, &cookie)
		cookie = http.Cookie{
			Name:  "refresh_token",
			Value: token.RefreshToken,
		}
		http.SetCookie(rw, &cookie)

		http.Redirect(rw, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) singIn() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		req := request{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		res, err := s.request("http://localhost:8080/singin", "POST", req)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/", http.StatusNotModified)
			return
		}
		defer res.Body.Close()
		token := &Token{}
		if err := json.NewDecoder(res.Body).Decode(token); err != nil {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			s.logger.Info(err)
			return
		}

		cookie := http.Cookie{
			Name:  "acsses_token",
			Value: token.AcssesToken,
		}
		http.SetCookie(rw, &cookie)
		cookie = http.Cookie{
			Name:  "refresh_token",
			Value: token.RefreshToken,
		}
		http.SetCookie(rw, &cookie)

		http.Redirect(rw, r, "/", http.StatusSeeOther)

	}
}

func (s *Server) request(url string, method string, data interface{}) (*http.Response, error) {
	b, _ := json.Marshal(data)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	c := &http.Client{}
	req.Header.Add("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s *Server) verify(rw http.ResponseWriter, r *http.Request) (bool, Token) {
	at, err := r.Cookie("acsses_token")
	if err != nil {
		return false, Token{}
	}
	rt, err := r.Cookie("refresh_token")
	if err != nil {
		return false, Token{}
	}

	token := Token{at.Value, rt.Value}
	res, err := s.request("http://localhost:8080/verify", "GET", token)
	if err != nil {
		s.logger.Info(err)
	}

	if res.StatusCode == http.StatusOK {
		token := &Token{}
		if err := json.NewDecoder(res.Body).Decode(token); err != nil {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			s.logger.Info(err)
			return false, Token{}
		}

		cookie := http.Cookie{
			Name:  "acsses_token",
			Value: token.AcssesToken,
		}
		http.SetCookie(rw, &cookie)
		cookie = http.Cookie{
			Name:  "refresh_token",
			Value: token.RefreshToken,
		}
		http.SetCookie(rw, &cookie)
		return true, *token
	}

	return false, Token{}
}

func (s *Server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})

}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
