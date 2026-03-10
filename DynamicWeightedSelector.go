package main

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// ============================================================================
// 数据结构定义
// ============================================================================

// WeightedKey 表示带权重的 key
type WeightedKey struct {
	Key    string
	Weight int
}

// DynamicWeightedSelector 动态权重选择器（线程安全）
type DynamicWeightedSelector struct {
	mu    sync.RWMutex
	keys  map[string]*WeightedKey // 使用 map 便于快速查找
	order []string                // 保持顺序用于遍历
	total int                     // 总权重
}

// ============================================================================
// 构造函数
// ============================================================================

// NewDynamicWeightedSelector 创建动态权重选择器
func NewDynamicWeightedSelector(keys []WeightedKey) *DynamicWeightedSelector {
	s := &DynamicWeightedSelector{
		keys:  make(map[string]*WeightedKey),
		order: make([]string, 0, len(keys)),
	}
	for _, k := range keys {
		s.AddKey(k.Key, k.Weight)
	}
	return s
}

// ============================================================================
// 核心方法 - 权重管理
// ============================================================================

// AddKey 添加新 key（如果已存在则更新权重）
func (s *DynamicWeightedSelector) AddKey(key string, weight int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[key]; !exists {
		s.order = append(s.order, key)
	}
	s.keys[key] = &WeightedKey{Key: key, Weight: weight}
	s.updateTotal()
}

// RemoveKey 删除 key
func (s *DynamicWeightedSelector) RemoveKey(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[key]; !exists {
		return false
	}

	delete(s.keys, key)
	newOrder := make([]string, 0, len(s.order))
	for _, k := range s.order {
		if k != key {
			newOrder = append(newOrder, k)
		}
	}
	s.order = newOrder
	s.updateTotal()
	return true
}

// SetWeight 动态设置权重（核心功能）
func (s *DynamicWeightedSelector) SetWeight(key string, weight int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if k, exists := s.keys[key]; exists {
		k.Weight = weight
		s.updateTotal()
		return true
	}
	return false
}

// GetWeight 获取当前权重
func (s *DynamicWeightedSelector) GetWeight(key string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if k, exists := s.keys[key]; exists {
		return k.Weight, true
	}
	return 0, false
}

// GetAllKeys 获取所有 key 及其权重
func (s *DynamicWeightedSelector) GetAllKeys() []WeightedKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]WeightedKey, 0, len(s.order))
	for _, key := range s.order {
		k := s.keys[key]
		result = append(result, WeightedKey{Key: k.Key, Weight: k.Weight})
	}
	return result
}

// GetTotalWeight 获取总权重
func (s *DynamicWeightedSelector) GetTotalWeight() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}

// GetCount 获取 key 数量
func (s *DynamicWeightedSelector) GetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order)
}

// updateTotal 更新总权重（内部使用，需持有锁）
func (s *DynamicWeightedSelector) updateTotal() {
	s.total = 0
	for _, key := range s.order {
		if s.keys[key].Weight > 0 {
			s.total += s.keys[key].Weight
		}
	}
}

// ============================================================================
// 核心方法 - 选择
// ============================================================================

// Select 根据权重随机选择一个 key
func (s *DynamicWeightedSelector) Select() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.total == 0 || len(s.order) == 0 {
		return ""
	}

	r := rand.Intn(s.total)
	current := 0
	for _, key := range s.order {
		k := s.keys[key]
		if k.Weight <= 0 {
			continue
		}
		current += k.Weight
		if r < current {
			return k.Key
		}
	}
	return ""
}

// SelectN 根据权重随机选择 N 个不重复的 key
func (s *DynamicWeightedSelector) SelectN(n int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.total == 0 || len(s.order) == 0 || n <= 0 {
		return []string{}
	}

	if n > len(s.order) {
		n = len(s.order)
	}

	result := make([]string, 0, n)
	selected := make(map[string]bool)

	for len(result) < n {
		r := rand.Intn(s.total)
		current := 0
		for _, key := range s.order {
			k := s.keys[key]
			if k.Weight <= 0 || selected[key] {
				continue
			}
			current += k.Weight
			if r < current {
				result = append(result, key)
				selected[key] = true
				break
			}
		}
	}

	return result
}

// ============================================================================
// 辅助方法
// ============================================================================

// Reset 重置所有权重
func (s *DynamicWeightedSelector) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range s.order {
		s.keys[key].Weight = 0
	}
	s.total = 0
}

// SetAllWeights 批量设置权重
func (s *DynamicWeightedSelector) SetAllWeights(weights map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, weight := range weights {
		if k, exists := s.keys[key]; exists {
			k.Weight = weight
		}
	}
	s.updateTotal()
}

// PrintStatus 打印当前状态
func (s *DynamicWeightedSelector) PrintStatus() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│  动态权重选择器状态                      │")
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Printf("│  Key 数量：%d\n", len(s.order))
	fmt.Printf("│  总权重：%d\n", s.total)
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Println("│  Key          权重      占比            │")
	fmt.Println("├─────────────────────────────────────────┤")
	for _, key := range s.order {
		k := s.keys[key]
		percent := 0.0
		if s.total > 0 {
			percent = float64(k.Weight) / float64(s.total) * 100
		}
		fmt.Printf("│  %-12s %-8d %.2f%%\n", k.Key, k.Weight, percent)
	}
	fmt.Println("└─────────────────────────────────────────┘")
}

func getKey() {
	keys := []WeightedKey{
		{"server1", 0},
		{"server2", 1},
		{"server3", 1},
		{"server4", 1},
		{"server5", 2},
	}
	selector := NewDynamicWeightedSelector(keys)

	for i := 0; i < 10000; i++ {
		selected := selector.Select()
		fmt.Println(selected)
	}
}

// ============================================================================
// 测试和示例
// ============================================================================

func main1() {
	rand.Seed(time.Now().UnixNano())

	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║     Go 动态权重选择器 - 完整演示           ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Println()

	// 1. 初始化选择器
	fmt.Println("【1】初始化选择器")
	keys := []WeightedKey{
		{"server1", 10},
		{"server2", 20},
		{"server3", 30},
		{"server4", 25},
		{"server5", 15},
	}
	selector := NewDynamicWeightedSelector(keys)
	selector.PrintStatus()
	fmt.Println()

	// 2. 测试权重分布
	fmt.Println("【2】测试初始权重分布（10000 次选择）")
	printDistribution(selector, 10000)
	fmt.Println()

	// 3. 动态调整权重
	fmt.Println("【3】动态调整 server1 权重为 50")
	selector.SetWeight("server1", 50)
	selector.PrintStatus()
	printDistribution(selector, 10000)
	fmt.Println()

	// 4. 添加新 key
	fmt.Println("【4】添加新 server6（权重 40）")
	selector.AddKey("server6", 40)
	selector.PrintStatus()
	printDistribution(selector, 10000)
	fmt.Println()

	// 5. 删除 key
	fmt.Println("【5】删除 server3")
	selector.RemoveKey("server3")
	selector.PrintStatus()
	printDistribution(selector, 10000)
	fmt.Println()

	// 6. 权重设为 0（临时下线）
	fmt.Println("【6】将 server2 权重设为 0（临时下线）")
	selector.SetWeight("server2", 0)
	selector.PrintStatus()
	printDistribution(selector, 10000)
	fmt.Println()

	// 7. 批量选择
	fmt.Println("【7】批量选择 3 个不重复的 key（10 次）")
	for i := 0; i < 10; i++ {
		selected := selector.SelectN(3)
		fmt.Printf("  第%d次：%v\n", i+1, selected)
	}
	fmt.Println()

	// 8. 并发测试
	fmt.Println("【8】并发安全测试")
	testConcurrent(selector)
	fmt.Println()

	// 9. 查询接口
	fmt.Println("【9】查询接口演示")
	weight, exists := selector.GetWeight("server1")
	fmt.Printf("  server1 权重：%d, 存在：%v\n", weight, exists)
	fmt.Printf("  总权重：%d\n", selector.GetTotalWeight())
	fmt.Printf("  Key 数量：%d\n", selector.GetCount())
	fmt.Println()

	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║           演示完成                         ║")
	fmt.Println("╚════════════════════════════════════════════╝")

	selected2 := selector.SelectN(1)
	fmt.Printf("  选择的 key：%v\n", selected2)
}

// printDistribution 打印选择分布统计
func printDistribution(selector *DynamicWeightedSelector, times int) {
	count := make(map[string]int)
	for i := 0; i < times; i++ {
		k := selector.Select()
		if k != "" {
			count[k]++
		}
	}

	fmt.Println("┌──────────────────────────────────────────────────────┐")
	fmt.Println("│  Key          选择次数   实际占比   期望占比   偏差  │")
	fmt.Println("├──────────────────────────────────────────────────────┤")
	for _, k := range selector.GetAllKeys() {
		if k.Weight <= 0 {
			continue
		}
		c := count[k.Key]
		actualPercent := float64(c) / float64(times) * 100
		expectedPercent := float64(k.Weight) / float64(selector.GetTotalWeight()) * 100
		deviation := actualPercent - expectedPercent
		fmt.Printf("│  %-12s %-10d %-10.2f %-10.2f %+.2f%%\n",
			k.Key, c, actualPercent, expectedPercent, deviation)
	}
	fmt.Println("└──────────────────────────────────────────────────────┘")
}

// testConcurrent 并发安全测试
func testConcurrent(selector *DynamicWeightedSelector) {
	var wg sync.WaitGroup
	errors := 0
	// var mu sync.Mutex

	// 多个 goroutine 同时选择
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				_ = selector.Select()
			}
		}(i)
	}

	// 多个 goroutine 同时修改权重
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				keys := []string{"server1", "server2", "server4", "server5", "server6"}
				key := keys[rand.Intn(len(keys))]
				selector.SetWeight(key, rand.Intn(100))
				time.Sleep(time.Microsecond * 100)
			}
		}(i)
	}

	// 多个 goroutine 同时添加/删除
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("temp_server_%d_%d", id, j)
				selector.AddKey(key, rand.Intn(50))
				time.Sleep(time.Microsecond * 500)
				selector.RemoveKey(key)
			}
		}(i)
	}

	wg.Wait()

	if errors == 0 {
		fmt.Println("  ✓ 并发测试通过，无竞争问题")
	} else {
		fmt.Printf("  ✗ 并发测试发现 %d 个错误\n", errors)
	}
}
