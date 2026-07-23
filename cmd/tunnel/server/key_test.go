package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadKeyCreatesAndReusesMissingAbsoluteFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "identities", "server.key")
	first, err := loadKey(filename)
	if err != nil {
		t.Fatalf("首次创建身份失败: %v", err)
	}
	second, err := loadKey(filename)
	if err != nil {
		t.Fatalf("重载身份失败: %v", err)
	}
	if string(first.Bytes()) != string(second.Bytes()) {
		t.Fatal("重载后身份发生变化")
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("读取身份文件状态失败: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("身份权限 = %o，期望 600", info.Mode().Perm())
	}
}
