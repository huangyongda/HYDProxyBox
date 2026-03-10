package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"apichange/database"
	"apichange/models"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

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
func loadServerConfig(configPath string) (*ServerConfig, error) {
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

	return &config.Server, nil
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

			// 调用 checkApikey 验证
			if err := checkApikey(orgtoken); err != nil {
				// token 无效，返回错误响应
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				errorMsg := err
				w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, errorMsg)))
				// w.Write([]byte(`{"error": "invalid token or expired "}`))
				return
			}

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
		req.Host = targetURL.Host

		// 轮询获取下一个 api_key
		apiKey, err := getNextAPIKey()
		if err != nil {
			log.Printf("获取 api_key 失败: %v", err)
			return
		}
		fmt.Println("使用 api_key:", apiKey)

		// 修改 apikey 头为轮询获取的值
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("apikey", apiKey)

		// 打印实际发送的请求（调试用）
		// dump, _ := httputil.DumpRequestOut(req, true)
		// log.Printf("发送的请求:\n%s", string(dump))
		// 其他 Header 保持不变
	}

	// 打印响应状态码
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("响应状态码: %d %s", resp.StatusCode, resp.Status)
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
	serverConfig, err := loadServerConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("加载服务器配置失败: %v", err)
	}

	// 目标后端服务地址（例如本地的另一个服务）
	backend := "https://api.minimaxi.com"

	// 创建中间件
	proxyMiddleware := ProxyMiddleware(backend)

	// 添加 token 验证中间件
	tokenAuthMiddleware := TokenAuthMiddleware()

	// 应用中间件链
	handler := tokenAuthMiddleware(proxyMiddleware(http.NotFoundHandler()))

	// 启动代理服务器
	addr := fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.ApiPort)
	log.Printf("启动代理服务器，监听地址: %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
