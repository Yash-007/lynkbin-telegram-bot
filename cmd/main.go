package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	telegram_bot "module/lynkbin-telegram-bot"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/go-telegram/ui/keyboard/inline"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/proxy"
)

type GenericResponse struct {
	Data    interface{} `json:"data"`
	Success bool        `json:"success"`
	Message string      `json:"message"`
}

type PostResponse struct {
	Data    map[string]interface{} `json:"data"`
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
}

type RecentPostsResponse struct {
	Data    []map[string]interface{} `json:"data"`
	Success bool                     `json:"success"`
	Message string                   `json:"message"`
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
	return "Welcome to Lynkbin!\n\n<b>For commands</b>: /start\n\n<b>For register</b>, visit: https://lynkbin.vercel.app/auth\n\n<b>For login</b>, use command:\n/login &lt;email&gt; &lt;password&gt;\n\n<b>For storing</b> your links or notes: just paste it here\n\n<b>View recent posts</b>: /recent \n\n<b>Long-press links to open in default browser</b>"
}

func isValidURL(msg string) bool {
	msg = strings.TrimSpace(msg)

	parsedURL, err := url.Parse(msg)
	if err != nil {
		fmt.Printf("Error parsing URL '%s': %v\n", msg, err)
		return false
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		fmt.Printf("Invalid URL scheme '%s' for URL: %s\n", parsedURL.Scheme, msg)
		return false
	}

	if parsedURL.Host == "" {
		fmt.Printf("Empty host in URL: %s\n", msg)
		return false
	}

	return true
}

var saveNoteKeyboard *inline.Keyboard

func initSaveNoteKeyboard(b *bot.Bot) {
	saveNoteKeyboard = inline.New(b).
		Row().
		Button("Yes", []byte("YES"), saveNoteKeyboardHandler).
		Button("No", []byte("NO"), saveNoteKeyboardHandler)
}

func main() {
	fmt.Println("Lynkbit Telegram Bot Starting...")

	if err := godotenv.Load("../.env"); err != nil {
		fmt.Printf("Warning: Error loading .env file: %v\n", err)
		fmt.Println("Continuing with system environment variables...")
	}

	server := &http.Server{
		Addr:    ":8081",
		Handler: nil,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Lynkbin Telegram Bot is running"))
	})

	go func() {
		fmt.Println("Starting HTTP server on port 8081")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	telegramBotFatherToken := os.Getenv("TELEGRAM_BOTFATHER_TOKEN")
	if telegramBotFatherToken == "" {
		fmt.Println("Error: TELEGRAM_BOTFATHER_TOKEN environment variable is not set")
		os.Exit(1)
	}

	// httpClient := createHTTPClientWithProxy("socks5://100.66.203.187:1088")

	opts := []bot.Option{
		bot.WithDefaultHandler(handler),
		bot.WithCheckInitTimeout(30 * time.Second),
		// bot.WithHTTPClient(30*time.Second, httpClient),
	}

	fmt.Println("Initializing Telegram bot...")
	b, err := bot.New(telegramBotFatherToken, opts...)
	if err != nil {
		fmt.Printf("Error creating bot: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Registering bot handlers...")
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if update == nil || update.Message == nil {
			fmt.Println("Error: Received nil update or message in /start handler")
			return
		}
		sendMessage(ctx, b, update.Message.Chat.ID, getBaseMsg())
	})

	b.RegisterHandler(bot.HandlerTypeMessageText, "/recent", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if update == nil || update.Message == nil {
			fmt.Println("Error: Received nil update or message in /recent handler")
			return
		}
		baseMsg := getBaseMsg()
		chatId := update.Message.Chat.ID

		redisUrl := os.Getenv("REDIS_URL")
		if redisUrl == "" {
			fmt.Printf("[ChatID: %d] Error: REDIS_URL environment variable is not set\n", chatId)
			sendMessage(ctx, b, chatId, "Service configuration error.")
			return
		}
		redisClient, err := telegram_bot.NewRedisClient(redisUrl)
		if err != nil {
			fmt.Printf("[ChatID: %d] Error creating Redis client: %v\n", chatId, err)
			sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
			return
		}

		email := getLoginEmail(redisClient, chatId)
		isLogin := email != ""
		fmt.Printf("[ChatID: %d] User login status: %v (email: %s)\n", chatId, isLogin, email)

		if !isLogin {
			fmt.Printf("[ChatID: %d] User not logged in, rejecting request\n", chatId)
			sendMessage(ctx, b, update.Message.Chat.ID, "You are not logged in. Please login first before posting to Lynkbin \n\n "+baseMsg)
			return
		}

		recentPostsResponse, err := getRecentPosts(update.Message.Chat.ID, email)
		if err != nil {
			sendMessage(ctx, b, update.Message.Chat.ID, "Unable to fetch recent posts.")
			return
		}

		posts := recentPostsResponse.Data
		if len(posts) == 0 {
			sendMessage(ctx, b, update.Message.Chat.ID, "No recent posts found.")
			return
		}
		var sb strings.Builder
		for i, post := range posts {
			content, ok := post["data"]
			if !ok {
				continue
			}
			sb.WriteString(fmt.Sprintf("<b>%d</b>. \n%s\n\n\n", i+1, content))
		}
		msg := sb.String()
		if msg == "" {
			msg = "No recent posts found."
		}
		sendMessage(ctx, b, update.Message.Chat.ID, msg)
	})

	// Start the bot
	fmt.Println("Telegram bot started successfully! Listening for messages...")
	b.Start(ctx)

	// Graceful shutdown
	fmt.Println("Received shutdown signal. Shutting down gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Error during HTTP server shutdown: %v\n", err)
	} else {
		fmt.Println("HTTP server shutdown successfully")
	}
}

func getLoginEmail(redisClient *redis.Client, chatId int64) string {
	loginKey := fmt.Sprintf("login:%d", chatId)
	email, err := redisClient.Get(context.Background(), loginKey).Result()
	if err != nil && err.Error() != "redis: nil" {
		fmt.Printf("[ChatID: %d] Error getting login from Redis: %v\n", chatId, err)
	}
	return email
}

func handler(ctx context.Context, b *bot.Bot, update *models.Update) {
	fmt.Printf("message: %s\n", update.Message.Text)
	fmt.Printf("message Id: %d\n", update.Message.Chat.ID)
	baseMsg := getBaseMsg()

	chatId := int64(update.Message.Chat.ID)
	msg := update.Message.Text

	msg = strings.Replace(msg, "\u00a0", " ", -1)
	msg = strings.TrimSpace(msg)

	// Get Redis URL
	redisUrl := os.Getenv("REDIS_URL")
	if redisUrl == "" {
		fmt.Printf("[ChatID: %d] Error: REDIS_URL environment variable is not set\n", chatId)
		sendMessage(ctx, b, chatId, "Service configuration error.")
		return
	}
	redisClient, err := telegram_bot.NewRedisClient(redisUrl)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error creating Redis client: %v\n", chatId, err)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}

	email := getLoginEmail(redisClient, chatId)
	isLogin := email != ""
	fmt.Printf("[ChatID: %d] User login status: %v (email: %s)\n", chatId, isLogin, email)

	if strings.HasPrefix(msg, "/login") {
		fmt.Printf("[ChatID: %d] Processing login request\n", chatId)
		loginResponse := hanldeLogin(msg, chatId, isLogin, *redisClient)
		sendMessage(ctx, b, chatId, loginResponse)
		return
	}

	if !isLogin {
		fmt.Printf("[ChatID: %d] User not logged in, rejecting request\n", chatId)
		sendMessage(ctx, b, update.Message.Chat.ID, "You are not logged in. Please login first before posting to Lynkbin \n\n "+baseMsg)
		return
	}

	if !isValidURL(msg) {
		fmt.Printf("[ChatID: %d] Invalid URL provided, user may want to save a note: %s\n", chatId, msg)
		initSaveNoteKeyboard(b)
		redisClient.Set(context.Background(), fmt.Sprintf("user_note:%d", chatId), msg, 120*time.Second)
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID:      chatId,
			Text:        "Do you want to save it as a note?",
			ReplyMarkup: saveNoteKeyboard,
		})
		return
	}

	escapedUrl := url.PathEscape(strings.TrimSpace(msg))
	fmt.Printf("[ChatID: %d] Creating post for URL: %s\n", chatId, escapedUrl)

	createPostPayload := map[string]any{
		"url":    escapedUrl,
		"is_url": true,
	}
	postLink, err := createLynkbinPost(chatId, email, createPostPayload)
	if err != nil {
		sendMessage(ctx, b, chatId, err.Error())
		return
	}
	responseMsg := fmt.Sprintf("Link saved successfully:%s\n\n <b>Long-press link to open in default browser</b>\n\n %s", postLink, baseMsg)
	sendMessage(ctx, b, chatId, responseMsg)
}

func createLynkbinPost(chatId int64, email string, payload map[string]any) (string, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error marshalling payload: %v\n", chatId, err)
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}

	serverUrl := os.Getenv("LYNKBIN_SERVER_URL")
	if serverUrl == "" {
		fmt.Printf("[ChatID: %d] Error: LYNKBIN_SERVER_URL environment variable is not set\n", chatId)
		return "", fmt.Errorf("service configuration error. Please contact support")
	}

	postUrl := serverUrl + "/posts"
	fmt.Printf("[ChatID: %d] Posting to Lynkbin API: %s\n", chatId, postUrl)
	req, err := http.NewRequest("POST", postUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("[ChatID: %d] Error creating HTTP request: %v\n", chatId, err)
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Id", "telegram-bot")
	req.Header.Set("X-Email-Id", email)

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		fmt.Printf("[ChatID: %d] Error posting to Lynkbin API: %v\n", chatId, resErr)
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		fmt.Printf("[ChatID: %d] Error: Unexpected status code from Lynkbin API\n", chatId)
		fmt.Printf("[ChatID: %d] Status Code: %d\n", chatId, resp.StatusCode)
		fmt.Printf("[ChatID: %d] Status: %s\n", chatId, resp.Status)
		if readErr != nil {
			fmt.Printf("[ChatID: %d] Error reading response body: %v\n", chatId, readErr)
		} else {
			fmt.Printf("[ChatID: %d] Response Body: %s\n", chatId, string(bodyBytes))
		}
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}

	var postResponse PostResponse
	err = json.NewDecoder(resp.Body).Decode(&postResponse)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error decoding response body: %v\n", chatId, err)
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}

	if !postResponse.Success {
		fmt.Printf("[ChatID: %d] Post creation failed. Server message: %s\n", chatId, postResponse.Message)
		return "", fmt.Errorf("unable to process your request. Please try again later")
	}

	postLink := postResponse.Data["post_link"].(string)
	fmt.Printf("[ChatID: %d] Successfully created post: %s\n", chatId, postLink)
	return postLink, nil
}

func getRecentPosts(chatId int64, email string) (RecentPostsResponse, error) {
	serverUrl := os.Getenv("LYNKBIN_SERVER_URL")
	if serverUrl == "" {
		fmt.Printf("[ChatID: %d] Error: LYNKBIN_SERVER_URL environment variable is not set\n", chatId)
		return RecentPostsResponse{}, fmt.Errorf("service configuration error. Please contact support")
	}

	postUrl := serverUrl + "/posts/recent"
	fmt.Printf("[ChatID: %d] Getting to Lynkbin API: %s\n", chatId, postUrl)
	req, err := http.NewRequest("GET", postUrl, nil)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error creating HTTP request: %v\n", chatId, err)
		return RecentPostsResponse{}, fmt.Errorf("unable to process your request. Please try again later")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Id", "telegram-bot")
	req.Header.Set("X-Email-Id", email)

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		fmt.Printf("[ChatID: %d] Error getting to Lynkbin API: %v\n", chatId, resErr)
		return RecentPostsResponse{}, fmt.Errorf("unable to process your request. Please try again later")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		fmt.Printf("[ChatID: %d] Error: Unexpected status code from Lynkbin API\n", chatId)
		fmt.Printf("[ChatID: %d] Status Code: %d\n", chatId, resp.StatusCode)
		fmt.Printf("[ChatID: %d] Status: %s\n", chatId, resp.Status)
		if readErr != nil {
			fmt.Printf("[ChatID: %d] Error reading response body: %v\n", chatId, readErr)
		} else {
			fmt.Printf("[ChatID: %d] Response Body: %s\n", chatId, string(bodyBytes))
		}
		return RecentPostsResponse{}, fmt.Errorf("unable to process your request. Please try again later")
	}

	var recentPostsResponse RecentPostsResponse
	err = json.NewDecoder(resp.Body).Decode(&recentPostsResponse)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error decoding response body: %v\n", chatId, err)
		return RecentPostsResponse{}, fmt.Errorf("unable to process your request. Please try again later")
	}

	if !recentPostsResponse.Success {
		fmt.Printf("[ChatID: %d] Getting recent posts failed. Server message: %s\n", chatId, recentPostsResponse.Message)
		return RecentPostsResponse{}, fmt.Errorf("unable to process your request. Please try again later")
	}

	fmt.Printf("[ChatID: %d] Successfully got recent posts: %+v\n", chatId, recentPostsResponse)
	return recentPostsResponse, nil
}

func hanldeLogin(msg string, chatId int64, isLogin bool, redisClient redis.Client) string {
	if isLogin {
		fmt.Printf("[ChatID: %d] User already logged in\n", chatId)
		return "You are already logged in. Paste your link here to store in Lynkbin"
	}

	msg = strings.TrimPrefix(msg, "/login")
	msg = strings.TrimLeft(msg, " ")

	email := strings.Split(msg, " ")[0]
	password := strings.TrimPrefix(msg, email+" ")

	if email == "" || password == "" {
		fmt.Printf("[ChatID: %d] Empty email or password provided\n", chatId)
		return "Email and password cannot be empty. Please use: /login &lt;email&gt; &lt;password&gt;"
	}

	fmt.Printf("[ChatID: %d] Attempting login for email: %s\n", chatId, email)

	loginPayload := map[string]string{
		"email":    email,
		"password": password,
	}
	jsonPayload, err := json.Marshal(loginPayload)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error marshalling login payload: %v\n", chatId, err)
		return "Unable to process login request"
	}

	loginUrl := os.Getenv("LYNKBIN_SERVER_URL")
	if loginUrl == "" {
		fmt.Printf("[ChatID: %d] Warning: LYNKBIN_SERVER_URL not set, using default: %s\n", chatId, loginUrl)
	}
	loginUrl = loginUrl + "/users/login"

	fmt.Printf("[ChatID: %d] Sending login request to: %s\n", chatId, loginUrl)
	req, err := http.NewRequest("POST", loginUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Printf("[ChatID: %d] Error creating login request: %v\n", chatId, err)
		return "Unable to process login request"
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Platform-Id", "telegram-bot")

	resp, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		fmt.Printf("[ChatID: %d] Error making login request: %v\n", chatId, resErr)
		return "Unable to process login request"
	}

	defer resp.Body.Close()

	fmt.Printf("[ChatID: %d] Login response status: %d %s\n", chatId, resp.StatusCode, resp.Status)

	var loginResponse GenericResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResponse)
	if err != nil {
		fmt.Printf("[ChatID: %d] Error decoding login response body: %v\n", chatId, err)
		return "Unable to process login request"
	}

	if !loginResponse.Success {
		fmt.Printf("[ChatID: %d] Login failed. Message: %s\n", chatId, loginResponse.Message)
		if loginResponse.Message == "User not found" {
			return "Email not found. Please register first before logging in:\nhttps://lynkbin.vercel.app/auth\n\n" + getBaseMsg()
		}
		return loginResponse.Message
	}

	loginKey := fmt.Sprintf("login:%d", chatId)
	err = redisClient.Set(context.Background(), loginKey, email, 0).Err()
	if err != nil {
		fmt.Printf("[ChatID: %d] Error saving login to Redis: %v\n", chatId, err)
		return "Unable to process login request"
	}

	fmt.Printf("[ChatID: %d] Login successful for email: %s\n", chatId, email)
	return "Login successful. Paste your link here to store in Lynkbin"
}

func saveNoteKeyboardHandler(ctx context.Context, b *bot.Bot, mes models.MaybeInaccessibleMessage, data []byte) {
	dataString := string(data)
	msg := ""
	baseMsg := getBaseMsg()
	chatId := mes.Message.Chat.ID
	redisClient, err := telegram_bot.NewRedisClient(os.Getenv("REDIS_URL"))
	if err != nil {
		fmt.Printf("[ChatID: %d] Error creating Redis client: %v\n", chatId, err)
		sendMessage(ctx, b, chatId, "Unable to process your request. Please try again later.")
		return
	}

	email := getLoginEmail(redisClient, chatId)
	if email == "" {
		fmt.Printf("[ChatID: %d] User not logged in, rejecting request\n", chatId)
		sendMessage(ctx, b, chatId, "You are not logged in. Please login first before posting to Lynkbin \n\n "+baseMsg)
		return
	}

	userNoteKey := fmt.Sprintf("user_note:%d", chatId)

	postLink := ""
	if dataString == "YES" {
		userNote, err := redisClient.Get(context.Background(), userNoteKey).Result()
		if err == redis.Nil {
			fmt.Printf("[ChatID: %d] Error getting user note: %v\n", chatId, err)
			msg = "Time limit expired. Please start over."
		} else if err != nil {
			fmt.Printf("[ChatID: %d] Error getting user note: %v\n", chatId, err)
			msg = "Unable to process your request. Please try again later."
		} else {
			payload := map[string]any{
				"notes": userNote,
			}
			postLink, err = createLynkbinPost(chatId, email, payload)
			if err != nil {
				msg = err.Error()
			} else {
				msg = fmt.Sprintf("Note saved successfully: %s\n\n <b>Long-press link to open in default browser</b>\n\n %s", postLink, baseMsg)
			}
		}
	} else {
		redisClient.Del(context.Background(), userNoteKey)
		msg = "No note saved"
	}
	sendMessage(ctx, b, chatId, msg)
}

func sendMessage(ctx context.Context, b *bot.Bot, chatId int64, text string) {
	_, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:    chatId,
		Text:      text,
		ParseMode: "HTML",
	})
	if err != nil {
		fmt.Printf("[ChatID: %d] Error sending message to user: %v\n", chatId, err)
		fmt.Printf("[ChatID: %d] Failed message text: %s\n", chatId, text)
	}
}
