// Package usage provides usage tracking and logging functionality for the CLI Proxy API server.
package usage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// persistPayload 是持久化文件的数据结构
type persistPayload struct {
	Version   int                `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
	Usage     StatisticsSnapshot `json:"usage"`
}

// Persister 负责统计信息的持久化加载和保存
type Persister struct {
	stats    *RequestStatistics
	filePath string
	interval time.Duration

	mu              sync.Mutex
	lastHash        string // 上次写入时的数据 hash，避免重复写入
	stopCh          chan struct{}
	stopped         bool
	wg              sync.WaitGroup
	persistOnChange bool // 是否仅在数据变化时持久化
}

// NewPersister 创建一个新的持久化管理器
// filePath: 持久化文件路径
// interval: 持久化间隔，最小 60 秒
func NewPersister(stats *RequestStatistics, filePath string, interval time.Duration) *Persister {
	if interval < 60*time.Second {
		interval = 60 * time.Second
	}
	return &Persister{
		stats:           stats,
		filePath:        filePath,
		interval:        interval,
		stopCh:          make(chan struct{}),
		persistOnChange: true,
	}
}

// Load 从文件加载统计信息并合并到内存中
// 返回加载的记录数和错误（如果有）
func (p *Persister) Load() (int64, error) {
	if p == nil || p.filePath == "" {
		return 0, nil
	}

	data, err := os.ReadFile(p.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("usage persister: no existing statistics file at %s", p.filePath)
			return 0, nil
		}
		return 0, err
	}

	if len(data) == 0 {
		return 0, nil
	}

	var payload persistPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0, err
	}

	// 版本检查（未来扩展用）
	if payload.Version != 1 {
		log.Warnf("usage persister: unknown version %d, attempting to load anyway", payload.Version)
	}

	result := p.stats.MergeSnapshot(payload.Usage)
	log.Infof("usage persister: loaded %d records from %s (skipped %d duplicates)", result.Added, p.filePath, result.Skipped)

	// 记录当前 hash，避免立即写回相同数据
	p.mu.Lock()
	p.lastHash = p.computeHash(payload.Usage)
	p.mu.Unlock()

	return result.Added, nil
}

// Start 启动定期持久化协程
func (p *Persister) Start(ctx context.Context) {
	if p == nil || p.filePath == "" {
		return
	}

	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	p.wg.Add(1)
	go p.runLoop(ctx)
}

func (p *Persister) runLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.persistNow(true)
			return
		case <-p.stopCh:
			p.persistNow(true)
			return
		case <-ticker.C:
			p.persistNow(false)
		}
	}
}

// Stop 停止定期持久化并执行最终保存
func (p *Persister) Stop() {
	if p == nil {
		return
	}

	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.stopCh)
	p.mu.Unlock()

	p.wg.Wait()
}

// Persist 立即执行一次持久化（公开方法）
func (p *Persister) Persist() error {
	return p.persistNow(true)
}

func (p *Persister) persistNow(force bool) error {
	if p == nil || p.stats == nil || p.filePath == "" {
		return nil
	}

	snapshot := p.stats.Snapshot()

	// 计算 hash 检查是否有变化
	hash := p.computeHash(snapshot)

	p.mu.Lock()
	lastHash := p.lastHash
	p.mu.Unlock()

	if !force && hash == lastHash {
		log.Debugf("usage persister: no changes, skipping persist")
		return nil
	}

	payload := persistPayload{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Usage:     snapshot,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Errorf("usage persister: failed to marshal statistics: %v", err)
		return err
	}

	// 确保目录存在
	dir := filepath.Dir(p.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Errorf("usage persister: failed to create directory %s: %v", dir, err)
			return err
		}
	}

	// 写入临时文件后重命名，保证原子性
	tmpFile := p.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		log.Errorf("usage persister: failed to write temporary file: %v", err)
		return err
	}

	if err := os.Rename(tmpFile, p.filePath); err != nil {
		log.Errorf("usage persister: failed to rename temporary file: %v", err)
		os.Remove(tmpFile)
		return err
	}

	p.mu.Lock()
	p.lastHash = hash
	p.mu.Unlock()

	log.Debugf("usage persister: saved %d requests to %s", snapshot.TotalRequests, p.filePath)
	return nil
}

func (p *Persister) computeHash(snapshot StatisticsSnapshot) string {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// 全局持久化器实例
var (
	globalPersister   *Persister
	globalPersisterMu sync.Mutex
)

// SetGlobalPersister 设置全局持久化器
func SetGlobalPersister(p *Persister) {
	globalPersisterMu.Lock()
	defer globalPersisterMu.Unlock()
	globalPersister = p
}

// GetGlobalPersister 获取全局持久化器
func GetGlobalPersister() *Persister {
	globalPersisterMu.Lock()
	defer globalPersisterMu.Unlock()
	return globalPersister
}

// StopGlobalPersister 停止全局持久化器
func StopGlobalPersister() {
	globalPersisterMu.Lock()
	p := globalPersister
	globalPersister = nil
	globalPersisterMu.Unlock()

	if p != nil {
		p.Stop()
	}
}
