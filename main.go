package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	// telegram_bot "module/lynkbin-telegram-bot"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/proxy"
)

type LoginResponse struct {
	Data    interface{} `json:"data"`
	Success bool        `json:"success"`
	Message string      `json:"message"`
}

type PostResponse struct {
	Data    map[string]interface{} `json:"data"`
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
}

func createHTTPClientWithProxy(proxyURL string) *http.Client {
	if proxyURL == "" {
		return &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Printf("Error parsing proxy URL: %v, using default client\n", err)
		return &http.Client{Timeout: 30 * time.Second}
	}

	var transport *http.Transport

	if parsedURL.Scheme == "socks5" {
		dialer, err := proxy.SOCKS5("tcp", parsedURL.Host, nil, proxy.Direct)
		if err != nil {
			fmt.Printf("Error creating SOCKS5 proxy: %v, using default client\n", err)
			return &http.Client{Timeout: 30 * time.Second}
		}

		transport = &http.Transport{
			Dial: dialer.Dial,
		}
	} else {
		transport = &http.Transport{
			Proxy: http.ProxyURL(parsedURL),
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func getBaseMsg() string {
	return "Welcome to Lynkbin!\n\n For register, visit: https://lynkbin.com/register\n\n For login, use command:\n /login <email> <password> \n\n for storing your links: just paste your link here"
}

func isValidURL(msg string) bool {
	msg = strings.TrimSpace(msg)

	parsedURL, err := url.Parse(msg)
	if err != nil {
		return false
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	if parsedURL.Host == "" {
		return false
	}

	return true
}

func main() {
	fmt.Println("Hello, World!")
	godotenv.Load()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	telegramBotFatherToken := os.Getenv("TELEGRAM_BOTFATHER_TOKEN")

	// httpClient := createHTTPClientWithProxy("socks5://10.101.116.69:1088")

	opts := []bot.Option{
		bot.WithDefaultHandler(handler),
		bot.WithCheckInitTimeout(30 * time.Second),
		// bot.WithHTTPClient(30*time.Second, httpClient),
	}
	b, err := bot.New(telegramBotFatherToken, opts...)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		sendMessage(ctx, b, update.Message.Chat.ID, getBaseMsg())
	})

	if err != nil {
		panic(err)
	}
	b.Start(ctx)
}

func handler(ctx context.Context, b *bot.Bot, update *models.Update) {
	fmt.Printf("message: %s\n", update.Message.Text)
	fmt.Printf("message Id: %d\n", update.Message.Chat.ID)
	baseMsg := getBaseMsg()

	msg := update.Message.Text
	msg = strings.Replace(msg, "\u00a0", " ", -1)
	msg = strings.TrimSpace(msg)

	chatId := int64(update.Message.Chat.ID)

	redisUrl := os.Getenv("REDIS_URL")
	fmt.Println("redisUrl: ", redisUrl)
	fmt.Printf("redisUrl: %s\n", redisUrl)
	redisClient := NewRedisClient(redisUrl)
	loginKey := fmt.Sprintf("login:%d", chatId)
	email, err := redisClient.Get(context.Background(), loginKey).Result()
	if err != nil {
		fmt.Printf("Error getting login: %v\n", err)
	}
	isLogin := email != ""

	if strings.HasPrefix(msg, "/login") {
		loginResponse := hanldeLogin(msg, chatId, isLogin, &redisClient)

		sendMessage(ctx, b, chatId, loginResponse)
		return
	}

	if !isLogin {
		sendMessage(ctx, b, update.Message.Chat.ID, "You are not logged in. Please login first before posting to Lynkbin \n\n "+baseMsg)
		return
	}

	if !isValidURL(msg) {
		sendMessage(ctx, b, chatId, "Invalid URL. Please enter a valid URL to store in Lynkbin \n\n "+baseMsg)
		return
	}

	escapedUrl := url.PathEscape(strings.TrimSpace(msg))

	createPostPayload := map[string]string{
		"url": escapedUrl,
	}
	jsonPayload, err := json.Marshal(createPostPayload)
	if err != nil {
		fmt.Printf("Error marshalling payload: %v\n", err)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}
	serverUrl := os.Getenv("LYNKBIN_SERVER_URL")
	req, err := http.NewRequest("POST", serverUrl+"/posts", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Id", "telegram-bot")
	req.Header.Set("X-Email-Id", email)

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		fmt.Printf("Error posting to Lynkbin: %v\n", resErr)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}

	var postResponse PostResponse
	err = json.NewDecoder(resp.Body).Decode(&postResponse)
	if err != nil {
		fmt.Printf("Error decoding response body: %v\n", err)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}

	if !postResponse.Success {
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}

	postLink := postResponse.Data["post_link"].(string)
	finalMsg := fmt.Sprintf("Your link has been stored on Lynkbin: %s", postLink)

	sendMessage(ctx, b, chatId, finalMsg)
}

func hanldeLogin(msg string, chatId int64, isLogin bool, redisClient *redis.Client) string {
	if isLogin {
		return "You are already logged in. Paste your link here to store in Lynkbin"
	}

	msg = strings.TrimPrefix(msg, "/login")
	msg = strings.TrimLeft(msg, " ")

	email := strings.Split(msg, " ")[0]
	password := strings.TrimPrefix(msg, email+" ")

	fmt.Printf("%s\n", email)
	fmt.Printf("%s\n", password)

	loginPayload := map[string]string{
		"email":    email,
		"password": password,
	}
	jsonPayload, err := json.Marshal(loginPayload)
	if err != nil {
		fmt.Printf("Error marshalling payload: %v\n", err)
		return "Unable to process login request"
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/users/login", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return "Unable to process login request"
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Id", "telegram-bot")

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		fmt.Printf("Error login: %v\n", resErr)
		return "Unable to process login request"
	}

	defer resp.Body.Close()
	var loginResponse LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResponse)
	if err != nil {
		fmt.Printf("Error decoding response body: %v\n", err)
		return "Unable to process login request"
	}
	if !loginResponse.Success {
		if loginResponse.Message == "User not found" {
			return "Email not found. Please register first before logging in:\nhttps://lynkbin.com/register\n\n" + getBaseMsg()
		}
		return loginResponse.Message
	}

	loginKey := fmt.Sprintf("login:%d", chatId)
	err = redisClient.Set(context.Background(), loginKey, email, 0).Err()
	if err != nil {
		fmt.Printf("Error setting login: %v\n", err)
		return "Unable to process login request"
	}
	return "Login successful. Paste your link here to store in Lynkbin"
}

func sendMessage(ctx context.Context, b *bot.Bot, chatId int64, text string) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatId,
		Text:   text,
	})
}
