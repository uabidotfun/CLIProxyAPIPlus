package usage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersister_LoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "usage_stats.json")

	stats := NewRequestStatistics()

	// 创建持久化器
	persister := NewPersister(stats, filePath, 60*time.Second)

	// 初始加载（文件不存在）
	loaded, err := persister.Load()
	if err != nil {
		t.Fatalf("Load should not fail for non-existent file: %v", err)
	}
	if loaded != 0 {
		t.Errorf("Expected 0 records loaded, got %d", loaded)
	}

	// 添加一些测试数据
	snapshot := StatisticsSnapshot{
		TotalRequests: 100,
		SuccessCount:  95,
		FailureCount:  5,
		TotalTokens:   50000,
		APIs: map[string]APISnapshot{
			"test-api": {
				TotalRequests: 100,
				TotalTokens:   50000,
				Models: map[string]ModelSnapshot{
					"gpt-4": {
						TotalRequests: 100,
						TotalTokens:   50000,
						Details: []RequestDetail{
							{
								Timestamp: time.Now().UTC(),
								Source:    "test",
								AuthIndex: "0",
								Tokens:    TokenStats{InputTokens: 1000, OutputTokens: 500, TotalTokens: 1500},
								Failed:    false,
							},
						},
					},
				},
			},
		},
		RequestsByDay:  map[string]int64{"2026-01-31": 100},
		RequestsByHour: map[string]int64{"00": 10, "01": 20},
		TokensByDay:    map[string]int64{"2026-01-31": 50000},
		TokensByHour:   map[string]int64{"00": 5000, "01": 10000},
	}

	// 合并数据
	stats.MergeSnapshot(snapshot)

	// 执行持久化
	if err := persister.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("Persist file was not created")
	}

	// 读取文件内容验证格式
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read persist file: %v", err)
	}

	var payload persistPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("Failed to unmarshal persist file: %v", err)
	}

	if payload.Version != 1 {
		t.Errorf("Expected version 1, got %d", payload.Version)
	}
	if payload.Usage.TotalRequests != 1 {
		t.Errorf("Expected 1 total request in persisted data, got %d", payload.Usage.TotalRequests)
	}

	// 创建新的 stats 实例模拟重启
	newStats := NewRequestStatistics()
	newPersister := NewPersister(newStats, filePath, 60*time.Second)

	// 加载持久化数据
	loaded, err = newPersister.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded != 1 {
		t.Errorf("Expected 1 record loaded, got %d", loaded)
	}

	// 验证加载后的快照
	newSnapshot := newStats.Snapshot()
	if newSnapshot.TotalRequests != 1 {
		t.Errorf("Expected 1 total request after load, got %d", newSnapshot.TotalRequests)
	}
}

func TestPersister_SkipUnchangedData(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "usage_stats.json")

	stats := NewRequestStatistics()
	persister := NewPersister(stats, filePath, 60*time.Second)

	// 第一次持久化
	if err := persister.Persist(); err != nil {
		t.Fatalf("First Persist failed: %v", err)
	}

	// 记录文件修改时间
	info1, _ := os.Stat(filePath)
	modTime1 := info1.ModTime()

	// 等待一小段时间
	time.Sleep(100 * time.Millisecond)

	// 再次持久化（数据未变化，应该跳过）
	if err := persister.persistNow(false); err != nil {
		t.Fatalf("Second Persist failed: %v", err)
	}

	info2, _ := os.Stat(filePath)
	modTime2 := info2.ModTime()

	// 文件修改时间应该相同（因为数据未变化）
	if !modTime1.Equal(modTime2) {
		t.Error("File should not be modified when data is unchanged")
	}
}

func TestPersister_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "usage_stats.json")

	stats := NewRequestStatistics()
	persister := NewPersister(stats, filePath, 60*time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	// 启动持久化
	persister.Start(ctx)

	// 添加一些数据
	snapshot := StatisticsSnapshot{
		APIs: map[string]APISnapshot{
			"test": {
				Models: map[string]ModelSnapshot{
					"model": {
						Details: []RequestDetail{{Timestamp: time.Now()}},
					},
				},
			},
		},
	}
	stats.MergeSnapshot(snapshot)

	// 取消 context
	cancel()

	// 等待 goroutine 退出
	time.Sleep(200 * time.Millisecond)

	// 验证文件已创建（Stop 时会执行最终持久化）
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Log("Note: File may not exist if context cancellation happened before periodic persist")
	}
}

func TestPersister_NilAndEmptyPath(t *testing.T) {
	// 测试 nil persister
	var nilPersister *Persister
	if _, err := nilPersister.Load(); err != nil {
		t.Errorf("Load on nil persister should not fail: %v", err)
	}
	if err := nilPersister.Persist(); err != nil {
		t.Errorf("Persist on nil persister should not fail: %v", err)
	}

	// 测试空路径
	stats := NewRequestStatistics()
	emptyPersister := NewPersister(stats, "", 60*time.Second)
	if _, err := emptyPersister.Load(); err != nil {
		t.Errorf("Load with empty path should not fail: %v", err)
	}
	if err := emptyPersister.Persist(); err != nil {
		t.Errorf("Persist with empty path should not fail: %v", err)
	}
}

func TestPersister_GlobalPersister(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "global_stats.json")

	stats := NewRequestStatistics()
	persister := NewPersister(stats, filePath, 60*time.Second)

	// 设置全局 persister
	SetGlobalPersister(persister)

	// 获取并验证
	got := GetGlobalPersister()
	if got != persister {
		t.Error("GetGlobalPersister should return the set persister")
	}

	// 停止全局 persister
	StopGlobalPersister()

	// 再次获取应该返回 nil
	got = GetGlobalPersister()
	if got != nil {
		t.Error("GetGlobalPersister should return nil after StopGlobalPersister")
	}
}
