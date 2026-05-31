package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	tokenTTL    = 15 * time.Minute
	sessionTTL  = 1 * time.Hour
	cookieName  = "session"
	redisPrefix = "cabinet:token:"
)

var (
	log         *logrus.Entry
	rdb         *redis.Client
	sessionKey  []byte
	baseURL     string
	usersURL    string
	analyticsURL string
	httpCli     = &http.Client{Timeout: 3 * time.Second}
	tpl         = template.Must(template.New("cab").Parse(cabinetHTML))
)

const cabinetHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Cabinet</title>
<style>body{font-family:system-ui;margin:2rem;max-width:48rem}
h1{margin:0 0 1rem} .row{padding:.25rem .5rem;border-bottom:1px solid #eee}
table{border-collapse:collapse;width:100%} td,th{text-align:left;padding:.25rem .5rem}</style>
</head><body>
<h1>Привет, {{.User.FirstName}} {{.User.LastName}}</h1>
<p>chat_id: <code>{{.User.ChatID}}</code> · username: <code>@{{.User.Username}}</code></p>
<h2>Активность за 30 дней</h2>
{{if .Buckets}}<table><thead><tr><th>дата</th><th>ответов</th></tr></thead><tbody>
{{range .Buckets}}<tr class="row"><td>{{.Date}}</td><td>{{.Count}}</td></tr>{{end}}
</tbody></table>{{else}}<p>Пока пусто.</p>{{end}}
</body></html>`

type userDTO struct {
	ChatID     int64  `json:"chatID"`
	FirstName  string `json:"firstName"`
	LastName   string `json:"lastName"`
	Username   string `json:"username"`
}

type bucket struct {
	Date  string `json:"date"`
	Count uint64 `json:"count"`
}

type pageData struct {
	User    userDTO
	Buckets []bucket
}

func initLogger() {
	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{})
	if lvl, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL")); err == nil {
		l.SetLevel(lvl)
	}
	name := os.Getenv("SERVICE_NAME")
	if name == "" {
		name = "web-admin"
	}
	log = l.WithField("service_name", name)
}

func initRedis() {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		log.Fatal("REDIS_ADDR is not set")
	}
	rdb = redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("REDIS_PASSWORD")})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.WithError(err).Fatal("Redis ping failed")
	}
}

func sign(chatID int64, exp time.Time) string {
	mac := hmac.New(sha256.New, sessionKey)
	fmt.Fprintf(mac, "%d|%d", chatID, exp.Unix())
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func issueSession(chatID int64) string {
	exp := time.Now().Add(sessionTTL)
	return fmt.Sprintf("%d.%d.%s", chatID, exp.Unix(), sign(chatID, exp))
}

func verifySession(raw string) (int64, error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return 0, errors.New("malformed")
	}
	chatID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	expUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, err
	}
	exp := time.Unix(expUnix, 0)
	if time.Now().After(exp) {
		return 0, errors.New("expired")
	}
	want := sign(chatID, exp)
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return 0, errors.New("bad signature")
	}
	return chatID, nil
}

func issueTokenHandler(c echo.Context) error {
	var body struct {
		ChatID int64 `json:"chat_id"`
	}
	if err := c.Bind(&body); err != nil || body.ChatID == 0 {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "chat_id required"})
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "rng failed"})
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	if err := rdb.Set(c.Request().Context(), redisPrefix+token, body.ChatID, tokenTTL).Err(); err != nil {
		log.WithError(err).Error("Redis set failed")
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "redis failed"})
	}
	link := fmt.Sprintf("%s/c/%s", strings.TrimRight(baseURL, "/"), token)
	return c.JSON(http.StatusOK, echo.Map{"token": token, "link": link, "expires_in": int(tokenTTL.Seconds())})
}

func consumeTokenHandler(c echo.Context) error {
	token := c.Param("token")
	ctx := c.Request().Context()
	chatIDStr, err := rdb.GetDel(ctx, redisPrefix+token).Result()
	if err != nil {
		return c.String(http.StatusUnauthorized, "Token invalid or expired")
	}
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		return c.String(http.StatusInternalServerError, "bad token payload")
	}
	c.SetCookie(&http.Cookie{
		Name:     cookieName,
		Value:    issueSession(chatID),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   false, // would be true behind real TLS Ingress
		SameSite: http.SameSiteLaxMode,
	})
	return c.Redirect(http.StatusFound, "/")
}

func cabinetHandler(c echo.Context) error {
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return c.String(http.StatusUnauthorized, "Сначала откройте кабинет по ссылке из бота (/cabinet)")
	}
	chatID, err := verifySession(cookie.Value)
	if err != nil {
		return c.String(http.StatusUnauthorized, "Сессия истекла, запросите новую ссылку через /cabinet в боте")
	}

	user, err := fetchUser(c.Request().Context(), chatID)
	if err != nil {
		log.WithError(err).WithField("chat_id", chatID).Error("users upstream failed")
		return c.String(http.StatusBadGateway, "Сервис пользователей недоступен")
	}
	buckets, err := fetchAggregates(c.Request().Context(), chatID)
	if err != nil {
		log.WithError(err).WithField("chat_id", chatID).Error("analytics upstream failed")
		buckets = nil
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return tpl.Execute(c.Response().Writer, pageData{User: user, Buckets: buckets})
}

func fetchUser(ctx context.Context, chatID int64) (userDTO, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%d", usersURL, chatID), nil)
	resp, err := httpCli.Do(req)
	if err != nil {
		return userDTO{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return userDTO{ChatID: chatID, FirstName: "user"}, nil
	}
	if resp.StatusCode >= 400 {
		return userDTO{}, fmt.Errorf("users status %d", resp.StatusCode)
	}
	var u userDTO
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return userDTO{}, err
	}
	if u.ChatID == 0 {
		u.ChatID = chatID
	}
	return u, nil
}

func fetchAggregates(ctx context.Context, chatID int64) ([]bucket, error) {
	since := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	until := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
	url := fmt.Sprintf("%s?chat_id=%d&since=%s&until=%s", analyticsURL, chatID, since, until)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("analytics status %d", resp.StatusCode)
	}
	var b []bucket
	return b, json.NewDecoder(resp.Body).Decode(&b)
}

func health(c echo.Context) error { return c.String(http.StatusOK, "ok") }

func main() {
	initLogger()
	initRedis()

	keyStr := os.Getenv("SESSION_KEY")
	if keyStr == "" {
		log.Fatal("SESSION_KEY is not set")
	}
	sessionKey = []byte(keyStr)

	baseURL = envOr("BASE_URL", "http://localhost:8080")
	usersURL = envOr("USERS_URL", "http://user-service/users")
	analyticsURL = envOr("ANALYTICS_URL", "http://analytics/aggregates")

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())

	e.POST("/internal/token", issueTokenHandler)
	e.GET("/c/:token", consumeTokenHandler)
	e.GET("/", cabinetHandler)
	e.GET("/healthz", health)
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	port := envOr("SERVER_PORT", "8080")

	srvErr := make(chan error, 1)
	go func() {
		log.WithField("port", port).Info("HTTP server starting")
		if err := e.Start(":" + port); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.WithField("signal", sig.String()).Info("Gracefully shutting down")
	case err := <-srvErr:
		log.WithError(err).Error("HTTP server failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = e.Shutdown(ctx)
	_ = rdb.Close()
	os.Exit(0)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
