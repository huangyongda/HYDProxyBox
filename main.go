package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
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

var targetURL string

// LLMConfig LLM 配置
type LLMConfig struct {
	Provider     string            `yaml:"provider"`
	APIURL       string            `yaml:"api_url"`
	APIKeys      []string          `yaml:"api_keys"`
	Timeout      int               `yaml:"timeout"`
	ModelMapping map[string]string `yaml:"model_mapping"`
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

// TokenAuthMiddleware 返回一个中间件，用于验证原始 token
func TokenAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//获取如果当前是/根目录时直接跳转302到另外一个页面
			fmt.Println("Path:", r.URL.Path)
			if r.URL.Path == "/" {
				http.Redirect(w, r, "http://120.24.86.32", http.StatusFound)
				return
			}
			// 提取原始 token
			hasXApiKey := r.Header.Get("x-api-key")
			authHeader := r.Header.Get("Authorization")
			orgtoken := ""
			if authHeader != "" {
				orgtoken = authHeader
				//Bearer 去掉
				orgtoken = orgtoken[7:]
			} else if hasXApiKey != "" {
				orgtoken = hasXApiKey
			}

			if strings.Contains(orgtoken, "wLDPWipw") {
				// token 无效，返回错误响应
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(fmt.Sprintf(`{"type":"error","error":{"type":"rate_limit_error","message":"当前处于高峰时段，Token Plan 的速率限制可能会临时收紧。请稍后重试，并请适当控制请求并发度。 (2062)","http_code":"429"},"request_id":"0612d1859464bc04afea711ef3fdbf1d"}`)))
				// w.Write([]byte(`{"error": "invalid token or expired "}`))
				return
			}

			// // 调用 checkApikey 验证
			// if err := checkApikey(orgtoken); err != nil {
			// 	// token 无效，返回错误响应
			// 	w.Header().Set("Content-Type", "application/json")
			// 	w.WriteHeader(http.StatusUnauthorized)
			// 	errorMsg := err
			// 	w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, errorMsg)))
			// 	// w.Write([]byte(`{"error": "invalid token or expired "}`))
			// 	return
			// }

			// token 有效，继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}

// ProxyMiddleware 返回一个中间件，将请求代理到 target 后端，并修改 apikey 头
func ProxyMiddleware(target string) func(http.Handler) http.Handler {
	// 解析后端地址（实际使用中应处理错误）
	targetURL, _ := url.Parse(target)

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorLog = log.New(os.Stderr, "", 0)

	// 保存默认的 Director，以便先执行必要的 URL/Host 改写
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {

		originalDirector(req) // 先执行默认的 Director（重写 URL 和 Host）

		// 确保 Host header 也被修改为目标后端
		// req.Host = targetURL.Host

		// // 轮询获取下一个 api_key
		// apiKey, err := getNextAPIKey()
		// if err != nil {
		// 	log.Printf("获取 api_key 失败: %v", err)
		// 	return
		// }
		// fmt.Println("使用 api_key:", apiKey)

		// 修改 apikey 头为轮询获取的值
		// req.Header.Set("Authorization", "Bearer "+apiKey)
		// req.Header.Set("apikey", apiKey)

		// 打印实际发送的请求（调试用）
		// dump, _ := httputil.DumpRequestOut(req, true)
		// log.Printf("发送的请求:\n%s", string(dump))
		// 其他 Header 保持不变
	}

	// 打印响应状态码
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("响应状态码: %d %s", resp.StatusCode, resp.Status)
		// 打印响应内容
		// dump, _ := httputil.DumpResponse(resp, true)
		// log.Printf("响应内容:\n%s", string(dump))
		// log.Printf("响应头:\n%s", resp.Header)

		return nil
	}

	// 返回中间件函数
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 直接使用反向代理处理请求，不调用 next
			proxy.ServeHTTP(w, r)
		})
	}
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

	serverConfig := appConfig.Server
	// // 目标后端服务地址（例如本地的另一个服务）
	// backend := appConfig.LLM.APIURL

	// // 创建中间件
	// proxyMiddleware := ProxyMiddleware(backend)

	// // 添加 token 验证中间件
	// tokenAuthMiddleware := TokenAuthMiddleware()

	// // 应用中间件链
	// handler := tokenAuthMiddleware(proxyMiddleware(http.NotFoundHandler()))

	// // 启动代理服务器
	addr := fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.ApiPort)
	// log.Printf("启动代理服务器，监听地址: %s", addr)
	// log.Fatal(http.ListenAndServe(addr, handler))

	r := gin.Default()

	r.POST("*path", proxyHandler)

	r.Run(addr)

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
	isStream, encoding, responseStr, statusCode := httpRequest(c, req)
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

func httpRequest(c *gin.Context, req *http.Request) (isStream bool, encoding, responseStr string, statusCode int) {
	// 创建新请求

	client := &http.Client{
		Timeout: 0, // 流式必须关闭超时
		//代理
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

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
		responseStr = handleStream(c, resp)
		isStream = true
	} else {
		responseStr = handleNormal(c, resp)
		isStream = false
	}
	return isStream, encoding, responseStr, resp.StatusCode
}

func handleNormal(c *gin.Context, resp *http.Response) (responseStr string) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": "read resp failed"})
		return
	}

	// ====== 日志记录（响应）======
	log.Println("==== RESPONSE ====")
	log.Println(string(body))
	responseStr = string(body)
	c.Writer.Write(body)
	return responseStr
}

func handleStream(c *gin.Context, resp *http.Response) (respStr string) {

	reader := bufio.NewReader(resp.Body)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(500, gin.H{"error": "stream not supported"})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	//Transfer-Encoding: chunked
	// Connection: keep-alive

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			// ====== 日志（流式）======
			log.Print(string(line))

			respStr += string(line)

			_, _ = c.Writer.Write(line)
			flusher.Flush()
		}

		if err != nil {
			if err != io.EOF {
				log.Println("stream error:", err)
			}
			break
		}
	}
	return respStr
}

func copyHeaders(src http.Header, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
