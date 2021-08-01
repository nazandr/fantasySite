package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
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
	fs := http.FileServer(http.Dir("web/assets"))

	s.router.Use(s.setRequestId)
	s.router.Use(s.loggerReq)
	s.router.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", fs))
	s.router.HandleFunc("/", s.indexHandler()).Methods("GET")
	s.router.HandleFunc("/collection", s.collection()).Methods("GET")
	s.router.HandleFunc("/singup", s.singUp()).Methods("POST")
	s.router.HandleFunc("/singin", s.singIn()).Methods("POST")
	s.router.HandleFunc("/logout", s.logOut()).Methods("GET")
	s.router.HandleFunc("/disenchant", s.disenchant()).Methods("POST")
	s.router.HandleFunc("/setFantasyTeam", s.setFantasyTeam()).Methods("POST")
	s.router.HandleFunc("/packs", s.packs()).Methods("GET")
	s.router.HandleFunc("/openCommonPack", s.openCommonPack()).Methods("GET")
	s.router.HandleFunc("/fantasyTeams", s.fantasyTeams()).Methods("GET")
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
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			User  *models.User
			Auth  bool
		}{
			Title: "Dota 2 Fantasy",
			CSS:   "/assets/index.css",
			Auth:  false,
		}
		a, _ := s.verify(rw, r)
		if a {
			user, err := s.userData(rw, r)
			if err != nil {
				return
			}
			data.User = user
		}

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
			"web/card.html",
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			Auth  bool
			User  *models.User
			Cards [][]models.PlayerCard
		}{
			Title: "Коллекция",
			CSS:   "/assets/collection.css",
			Auth:  true,
		}
		a, _ := s.verify(rw, r)

		if !a {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
		}
		user, err := s.userData(rw, r)
		if err != nil {
			return
		}
		data.User = user
		data.Cards = user.CardsCollection
		for i := 0; i < len(data.Cards); i++ {
			for idx := 0; idx < len(data.Cards[i]); idx++ {
				data.Cards[i][idx].CutId = data.Cards[i][idx].Id.Hex()
			}
		}

		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) disenchant() http.HandlerFunc {
	type respond struct {
		AcssesToken  string `json:"acsses_token"`
		RefreshToken string `json:"refresh_token"`
		ID           string `json:"card_id"`
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		cook := r.Cookies()

		resp := respond{
			AcssesToken:  cook[2].Value,
			RefreshToken: cook[3].Value,
			ID:           r.FormValue("card_id"),
		}
		resp.ID = strings.TrimLeft(resp.ID, "ObjectID(\"")
		resp.ID = strings.TrimRight(resp.ID, "\")")

		res, err := s.request("http://localhost:8080/auth/disenchant", "POST", resp)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/collection", http.StatusFound)
			return
		}
		defer res.Body.Close()
		http.Redirect(rw, r, "/collection", http.StatusFound)
	}
}
func (s *Server) openCommonPack() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		a, token := s.verify(rw, r)

		if !a {
			http.Redirect(rw, r, "/", http.StatusFound)
			return
		}
		res, err := s.request("http://localhost:8080/auth/openCommonPack", "POST", token)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/collection", http.StatusFound)
			return
		}
		defer res.Body.Close()

		tpl := template.Must(template.ParseFiles(
			"web/packs.html",
			"web/card.html",
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			User  *models.User
			Auth  bool
			Open  bool
			Pack  *[]models.PlayerCard
		}{
			Title: "Паки",
			Open:  true,
			CSS:   "/assets/packs.css",
			Auth:  true,
		}

		user, err := s.userData(rw, r)
		if err != nil {
			return
		}
		data.User = user

		pack := &[]models.PlayerCard{}
		if err := json.NewDecoder(res.Body).Decode(pack); err != nil {
			http.Redirect(rw, r, "/", http.StatusFound)
			s.logger.Info(err)
			return
		}
		data.Pack = pack
		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) packs() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tpl := template.Must(template.ParseFiles(
			"web/packs.html",
			"web/card.html",
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title string
			CSS   string
			User  *models.User
			Open  bool
			Auth  bool
		}{
			Title: "Паки",
			// CSS:   "/assets/packs.css",
			Auth: true,
			Open: false,
		}
		a, _ := s.verify(rw, r)

		if !a {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			return
		}
		user, err := s.userData(rw, r)
		if err != nil {
			return
		}
		data.User = user

		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) fantasyTeams() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tpl := template.Must(template.ParseFiles(
			"web/fantasy.html",
			"web/fantasyTeamCard.html",
			"web/header.html",
			"web/footer.html",
		))
		data := struct {
			Title       string
			CSS         string
			User        *models.User
			Auth        bool
			TodaysTeam  bool
			MidPlayers  [][][]models.PlayerCard
			CorePlayers [][][]models.PlayerCard
			SupPlayers  [][][]models.PlayerCard
		}{
			Title: "Фэнтази команды",
			// CSS:   "/assets/packs.css",
			Auth:       true,
			TodaysTeam: false,
		}
		au, _ := s.verify(rw, r)

		if !au {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			return
		}

		user, err := s.userData(rw, r)
		if err != nil {
			return
		}

		a := user.Teams
		for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
			a[i], a[j] = a[j], a[i]
		}
		user.Teams = a

		if len(user.Teams) == 0 {
			user.Teams = make([]models.FantasyTeam, 1)
		}
		if user.Teams[0].Date.Truncate(24*time.Hour) == time.Now().UTC().Truncate(24*time.Hour) {
			data.TodaysTeam = true
		} else {
			for i := 0; i < len(user.CardsCollection); i++ {
				for in := 0; in < len(user.CardsCollection[i]); in++ {
					user.CardsCollection[i][in].CutId = user.CardsCollection[i][in].Id.Hex()
				}
			}
			for i := 0; i < 1; i++ {
				data.MidPlayers = append(data.MidPlayers, user.CardsCollection)
			}
			for i := 0; i < 2; i++ {
				data.CorePlayers = append(data.CorePlayers, user.CardsCollection)
			}
			for i := 0; i < 2; i++ {
				data.SupPlayers = append(data.SupPlayers, user.CardsCollection)
			}
		}
		data.User = user
		if err := tpl.Execute(rw, data); err != nil {
			s.logger.Info(err)
		}
	}
}

func (s *Server) setFantasyTeam() http.HandlerFunc {
	type respond struct {
		AcssesToken  string              `json:"acsses_token"`
		RefreshToken string              `json:"refresh_token"`
		Team         []models.PlayerCard `json:"team"`
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		cook := r.Cookies()
		r.ParseForm()
		resp := respond{
			AcssesToken:  cook[0].Value,
			RefreshToken: cook[1].Value,
		}

		user, err := s.userData(rw, r)
		if err != nil {
			return
		}

		for i := 0; i < len(user.CardsCollection); i++ {
			for _, v := range r.Form {
				for in := 0; in < len(user.CardsCollection[i]); in++ {
					if v[0] == user.CardsCollection[i][in].Id.Hex() {
						resp.Team = append(resp.Team, user.CardsCollection[i][in])
					}
				}
			}
		}

		res, err := s.request("http://localhost:8080/auth/setFantasyTeam", "POST", resp)
		if err != nil {
			s.logger.Info(err)
			http.Redirect(rw, r, "/", http.StatusFound)
			return
		}
		defer res.Body.Close()
		http.Redirect(rw, r, "/fantasyTeams", http.StatusFound)
	}
}

func (s *Server) userData(rw http.ResponseWriter, r *http.Request) (*models.User, error) {
	a, token := s.verify(rw, r)
	user := &models.User{}
	if !a {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return user, fmt.Errorf("Unauthorized")
	}
	res, err := s.request("http://localhost:8080/auth/user", "GET", token)

	if err != nil {
		s.logger.Info(err)
		http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
		return user, err
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(user); err != nil {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		s.logger.Info(err)
		return user, err
	}

	return user, nil
}

// Регистрация
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
			http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer res.Body.Close()
		token := &Token{}
		if err := json.NewDecoder(res.Body).Decode(token); err != nil {
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			s.logger.Info(err)
			return
		}

		s.SetToken(rw, token)

		http.Redirect(rw, r, "/", http.StatusSeeOther)
	}
}

// Вход
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
			http.Redirect(rw, r, "/", http.StatusFound)
			return
		}
		defer res.Body.Close()
		token := &Token{}
		if err := json.NewDecoder(res.Body).Decode(token); err != nil {
			http.Redirect(rw, r, "/", http.StatusFound)
			s.logger.Info(err)
			return
		}

		s.SetToken(rw, token)

		http.Redirect(rw, r, "/", http.StatusFound)

	}
}

func (s *Server) logOut() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		c := &http.Cookie{
			Name:    "acsses_token",
			Value:   "",
			Expires: time.Unix(0, 0),
		}

		http.SetCookie(rw, c)
		c = &http.Cookie{
			Name:    "refresh_token",
			Value:   "",
			Expires: time.Unix(0, 0),
		}

		http.SetCookie(rw, c)
		http.Redirect(rw, r, "/", http.StatusFound)
	}
}

func (s *Server) request(url string, method string, data interface{}) (*http.Response, error) {
	b, _ := json.Marshal(data)
	// fmt.Print(string(b))

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
	if token.AcssesToken == "" {
		return false, Token{}
	}
	res, err := s.request("http://localhost:8080/verify", "GET", token)
	if err != nil {
		s.logger.Info(err)
		return false, Token{}
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		t := &Token{}
		if err := json.NewDecoder(res.Body).Decode(t); err != nil {
			s.logger.Info(err)
			return false, Token{}
		}
		s.logger.Info("veryfy set token " + t.RefreshToken)
		s.SetToken(rw, t)
		return true, *t
	}

	return false, Token{}
}

func (s *Server) SetToken(rw http.ResponseWriter, token *Token) {
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
}
