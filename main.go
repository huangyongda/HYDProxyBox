package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"apichange/database"
	"apichange/models"

	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

var (
	targetURL string
	// 重试配置
	maxRetries        int
	retryInitialDelay time.Duration
	retryMaxDelay     time.Duration
)

// LLMConfig LLM 配置
type LLMConfig struct {
	Provider          string            `yaml:"provider"`
	APIURL            string            `yaml:"api_url"`
	APIKeys           []string          `yaml:"api_keys"`
	Timeout           int               `yaml:"timeout"`
	ModelMapping      map[string]string `yaml:"model_mapping"`
	MaxRetries        int               `yaml:"max_retries"`
	RetryInitialDelay int               `yaml:"retry_initial_delay"`
	RetryMaxDelay     int               `yaml:"retry_max_delay"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	ApiPort int    `yaml:"api_port"`
}

// AppConfig 应用配置
type AppConfig struct {
	Server ServerConfig `yaml:"server"`
	LLM    LLMConfig    `yaml:"llm"`
}

// APIErrorResponse API错误响应结构
type APIErrorResponse struct {
	Error     APIErrorDetail `json:"error"`
	RequestID string         `json:"request_id,omitempty"`
}

// APIErrorDetail 错误详情
type APIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

var (
	mu          sync.RWMutex // 1. 读写锁，保护配置数据
	lastLoad    time.Time    // 记录上次加载时间
	apiKeys     []string
	apiKeyIndex uint32
	apiKeysOnce sync.Once
	apiKeysErr  error
)

// loadAPIKeys 加载配置文件中的 api_keys
func loadAPIKeys(configPath string) ([]string, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config AppConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	if len(config.LLM.APIKeys) == 0 {
		return nil, fmt.Errorf("配置文件中没有找到 api_keys")
	}

	return config.LLM.APIKeys, nil
}

// loadServerConfig 加载服务器配置
func loadServerConfig(configPath string) (*AppConfig, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config AppConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	if config.Server.ApiPort == 0 {
		config.Server.ApiPort = 3000 // 默认端口
	}

	// 设置重试配置默认值
	if config.LLM.MaxRetries == 0 {
		config.LLM.MaxRetries = 3
	}
	if config.LLM.RetryInitialDelay == 0 {
		config.LLM.RetryInitialDelay = 1000 // 1秒
	}
	if config.LLM.RetryMaxDelay == 0 {
		config.LLM.RetryMaxDelay = 10000 // 10秒
	}

	return &config, nil
}

// getNextAPIKey 轮询获取下一个 api_key
func getNextAPIKey() (string, error) {
	// 2. 快速检查：是否需要重新加载 (先加读锁读取时间)
	mu.RLock()
	keys := apiKeys
	err := apiKeysErr
	loadedTime := lastLoad
	mu.RUnlock()

	// 3. 判断条件：列表为空 或 距离上次加载超过 30 秒
	if len(keys) == 0 || time.Since(loadedTime) > 30*time.Second {
		// 4. 需要加载，升级为写锁 (Double-Check 防止并发重复加载)
		mu.Lock()
		// 再次检查，因为可能在排队锁的时候其他协程已经加载过了
		if len(apiKeys) == 0 || time.Since(lastLoad) > 30*time.Second {
			apiKeys, apiKeysErr = loadAPIKeys("configs/config.yaml")
			lastLoad = time.Now()
		}
		// 更新本地变量以使用最新数据
		keys = apiKeys
		err = apiKeysErr
		mu.Unlock()
	}

	// 5. 错误处理
	if err != nil {
		return "", err
	}

	// 6. 安全防御：防止除零错误 (Panic)
	if len(keys) == 0 {
		return "", errors.New("no api keys available in config")
	}

	// 7. 轮询获取 Key (原子操作保证并发安全)
	index := atomic.AddUint32(&apiKeyIndex, 1) - 1
	return keys[index%uint32(len(keys))], nil
}

func checkApikey(token string) error {
	// 从数据库查询 api_keys 表验证 token
	var apiKey models.APIKey
	result := database.GetDB().Where("`key_value` = ?", token).First(&apiKey)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return fmt.Errorf("invalid token")
		}
		return fmt.Errorf("database error: %v", result.Error)
	}

	// 关联查询 users 表获取用户的 request_count 和 request_limit
	var user models.User
	if err := database.GetDB().First(&user, apiKey.UserID).Error; err != nil {
		return fmt.Errorf("user not found")
	}
	//如果用户已经过期
	if user.ExpiresAt != nil && user.ExpiresAt.Before(database.GetDB().NowFunc()) {
		return fmt.Errorf("user has expired")
	}

	// 检查用户配额
	if user.RequestCount >= user.RequestLimit {
		return fmt.Errorf("request limit exceeded")
	}
	if err := database.GetDB().Model(&user).Where("id = ?", user.ID).Update("request_count", gorm.Expr("request_count + 1")).Error; err != nil {
		return fmt.Errorf("database error: %v", err)
	}
	//插入日志
	usageLog := models.UsageLog{
		APIKeyID:         apiKey.ID,
		UserID:           user.ID,
		Model:            "**",
		PromptTokens:     0,
		CompletionTokens: 0,
		TotalTokens:      0,
		LatencyMs:        0,
		Cost:             0,
	}
	if err := database.GetDB().Create(&usageLog).Error; err != nil {
		return fmt.Errorf("database error: %v", err)
	}

	return nil
}

func main() {
	// 初始化数据库连接
	if err := database.Init("configs/config.yaml"); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	// 加载服务器配置
	appConfig, err := loadServerConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("加载服务器配置失败: %v", err)
	}

	targetURL = appConfig.LLM.APIURL

	// 设置重试配置
	maxRetries = appConfig.LLM.MaxRetries
	retryInitialDelay = time.Duration(appConfig.LLM.RetryInitialDelay) * time.Millisecond
	retryMaxDelay = time.Duration(appConfig.LLM.RetryMaxDelay) * time.Millisecond

	serverConfig := appConfig.Server
	// // 启动代理服务器
	addr := fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.ApiPort)
	log.Printf("启动代理服务器，监听地址: %s", addr)
	// log.Fatal(http.ListenAndServe(addr, handler))

	r := gin.Default()

	r.POST("*path", proxyHandler)

	r.Run(addr)

}

// shouldRetry 判断是否应该重试（非流式响应）
func shouldRetry(responseStr string, statusCode int) bool {
	if statusCode != http.StatusOK {
		return false
	}

	var apiError APIErrorResponse
	if err := json.Unmarshal([]byte(responseStr), &apiError); err != nil {
		return false
	}

	return apiError.Error.Code == "1305"
}

// shouldRetryStream 检测流式响应前2个chunk是否包含错误
func shouldRetryStream(combined string) bool {
	// 尝试从 SSE 格式中提取 JSON 内容
	// SSE 格式通常是: "data: {...}\n\n"
	lines := strings.Split(combined, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			jsonStr := strings.TrimPrefix(line, "data:")
			jsonStr = strings.TrimSpace(jsonStr)

			var apiError APIErrorResponse
			if err := json.Unmarshal([]byte(jsonStr), &apiError); err == nil {
				if apiError.Error.Code == "1305" {
					return true
				}
			}
		}
	}
	return false
}

// executeWithRetry 带重试的HTTP请求执行
func executeWithRetry(c *gin.Context, req *http.Request, maxRetries int, initialDelay, maxDelay time.Duration) (bool, string, string, int) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 指数退避延迟
			delay := time.Duration(int(initialDelay) * (1 << (attempt - 1)))
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("重试第 %d 次，等待 %v 后重试", attempt, delay)
			time.Sleep(delay)

			// 重新构建请求（可能需要新的API key）
			apiKey, err := getNextAPIKey()
			if err != nil {
				log.Printf("重试时获取 API key 失败: %v", err)
			} else {
				hasXApiKey := c.Request.Header.Get("x-api-key") != ""
				if hasXApiKey {
					req.Header.Set("x-api-key", apiKey)
				} else {
					req.Header.Set("Authorization", "Bearer "+apiKey)
				}
			}
		}

		isStream, encoding, responseStr, statusCode, needRetry := httpRequest(c, req)

		// 使用 needRetry 标志判断
		if !needRetry {
			return isStream, encoding, responseStr, statusCode
		}

		log.Printf("检测到可重试错误 (1305)，准备重试")
	}

	log.Printf("达到最大重试次数 %d", maxRetries)
	return false, "", "", http.StatusInternalServerError
}

func proxyHandler(c *gin.Context) {
	start := time.Now()

	// 读取请求 body
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": "read body failed"})
		return
	}

	// ===== 判断类型 =====
	hasXApiKey := c.Request.Header.Get("x-api-key") != ""
	authHeader := c.Request.Header.Get("Authorization")

	if hasXApiKey {

	} else if strings.HasPrefix(authHeader, "Bearer ") {

	} else {
		c.String(http.StatusBadRequest, "Missing API key header")
		return
	}

	url, err := url.Parse(targetURL)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	url.Path = c.Request.URL.Path
	url.RawQuery = c.Request.URL.RawQuery

	fmt.Println("请求地址:", url.String())

	// ====== 日志记录（请求）======
	log.Println("==== REQUEST ====")
	log.Println(string(bodyBytes))

	req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(bodyBytes))
	if err != nil {
		c.JSON(500, gin.H{"error": "create request failed"})
		return
	}

	// ====== Header 处理 ======
	copyHeaders(c.Request.Header, req.Header)

	apiKey, err := getNextAPIKey()
	if err != nil {
		log.Printf("获取 api_key 失败: %v", err)
		c.JSON(500, gin.H{"error": "获取 api_key 失败"})
		return
	}
	fmt.Println("使用 api_key:", apiKey)
	if hasXApiKey {
		// Anthropic
		req.Header.Set("x-api-key", apiKey)
		req.Header.Del("Authorization")
	} else {
		// OpenAI
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Del("x-api-key")
	}
	// 使用重试逻辑执行请求
	isStream, encoding, responseStr, statusCode := executeWithRetry(c, req, maxRetries, retryInitialDelay, retryMaxDelay)
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "request failed"})
		return
	}
	responseStr, err = decrypt(encoding, responseStr)
	if err != nil {
		c.JSON(500, gin.H{"error": "decrypt failed"})
		return
	}
	if isStream == false {
		fmt.Println("响应内容:", responseStr)
	}
	//{"error":{"code":"1305","message":"该模型当前访问量过大，请您稍后再试"},"request_id":"202604081407415956ef68960146c8"}

	fmt.Println("响应状态码:", statusCode, ",响应内容:", responseStr)

	log.Println("耗时:", time.Since(start))
}

// 解密http内容
func decrypt(encoding string, content string) (string, error) {
	bodyBytes := []byte(content)
	responseBody := content
	if encoding == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			fmt.Println("gzip reader error:", err)
			return "", err
		}
		defer reader.Close()
		var resultStr []byte
		resultStr, _ = io.ReadAll(reader)
		responseBody = string(resultStr)
	}
	if encoding == "br" {
		reader := brotli.NewReader(bytes.NewReader(bodyBytes))
		resultStr, err := io.ReadAll(reader)
		if err != nil {
			fmt.Println("brotli error:", err)
			return "", err
		}
		responseBody = string(resultStr)
	}
	return responseBody, nil
}

func httpRequest(c *gin.Context, req *http.Request) (isStream bool, encoding, responseStr string, statusCode int, needRetry bool) {
	// 创建新请求

	client := &http.Client{
		Timeout: 0, // 流式必须关闭超时
		//代理
		// Transport: &http.Transport{
		// 	Proxy: http.ProxyFromEnvironment,
		// },
	}
	startTime := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	// ====== 返回 header ======
	copyHeaders(resp.Header, c.Writer.Header())
	c.Status(resp.StatusCode)

	// 判断是否是流式
	contentType := resp.Header.Get("Content-Type")
	encoding = resp.Header.Get("Content-Encoding")
	// 打印header
	log.Println("响应头:")
	for key, values := range resp.Header {
		for _, value := range values {
			log.Printf("%s: %s\n", key, value)
		}
	}

	if strings.Contains(contentType, "text/event-stream") {
		responseStr, needRetry = handleStream(c, resp, startTime)
		isStream = true
	} else {
		responseStr, needRetry = handleNormal(c, resp)
		isStream = false
	}
	return isStream, encoding, responseStr, resp.StatusCode, needRetry
}

func handleNormal(c *gin.Context, resp *http.Response) (responseStr string, needRetry bool) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// c.JSON(500, gin.H{"error": "read resp failed"})
		fmt.Println("读取响应内容失败:", err)
		return "", false
	}

	// ====== 日志记录（响应）======
	// log.Println("==== RESPONSE ====")
	// log.Println(string(body))
	responseStr = string(body)
	// c.Writer.Write(body)

	// 检测是否需要重试
	needRetry = shouldRetry(responseStr, resp.StatusCode)
	return responseStr, needRetry
}

func handleStream(c *gin.Context, resp *http.Response, streamStart time.Time) (respStr string, needRetry bool) {
	reader := bufio.NewReader(resp.Body)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(500, gin.H{"error": "stream not supported"})
		return "", false
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")

	// 预检测阶段：读取前2个chunk
	var firstChunks []string
	chunkCount := 0
	for chunkCount < 2 {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Println("预检测阶段读取错误:", err)
			}
			break
		}
		if len(line) > 0 {
			firstChunks = append(firstChunks, string(line))
			chunkCount++
		}
	}

	// 检测前2个chunk是否包含错误
	combined := strings.Join(firstChunks, "")
	if shouldRetryStream(combined) {
		return combined, true // 需要重试
	}

	// 指标统计
	var firstTokenTime time.Time
	firstTokenReceived := false
	ttft := time.Duration(0)

	// 先发送已读取的前2个chunk
	for _, chunk := range firstChunks {
		if !firstTokenReceived && len(chunk) > 4 {
			firstTokenTime = time.Now()
			firstTokenReceived = true
			ttft = firstTokenTime.Sub(streamStart)
		}
		respStr += chunk
		c.Writer.Write([]byte(chunk))
		flusher.Flush()
	}

	// 继续读取剩余的流
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineStr := string(line)

			if !firstTokenReceived && len(lineStr) > 4 {
				firstTokenTime = time.Now()
				firstTokenReceived = true
				ttft = firstTokenTime.Sub(streamStart)
			}

			respStr += lineStr
			c.Writer.Write(line)
			flusher.Flush()
		}

		if err != nil {
			if err != io.EOF {
				log.Println("stream error:", err)
			}
			break
		}
	}

	log.Printf("  首字 %v", ttft)

	return respStr, false // 不需要重试
}

func copyHeaders(src http.Header, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
