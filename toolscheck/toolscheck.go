// Package toolscheck 是外部工具钉版清单的加载与校验（v0.6.3，FORANG 自研）。
//
// 清单见 packaging/tools-manifest.json：每条含 name/purpose/version/platform/
// sha256/path/env/category。校验规则：
//   - 解析路径：env 指定的绝对/相对路径优先，其次 dataDir/path，最后 PATH 查找；
//   - sha256 为空 = 未钉版：只警告（状态 unpinned），不阻断；
//   - sha256 已填：文件存在时算哈希比对，不匹配报 mismatch（硬失败，
//     部署机换了二进制没同步清单时能第一时间发现）；
//   - 文件不存在：状态 missing，只警告（工具缺失不该拦住整个后端启动，
//     用到它的功能时再诚实报错）。
//
// 启动自检与 artex doctor 共用同一 Check；doctor 对 missing/unpinned 只警告，
// 对 mismatch 与数据库/目录类硬失败才 exit 1。
package toolscheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Tool 是清单里的一条外部工具。
type Tool struct {
	Name     string `json:"name"`
	Purpose  string `json:"purpose"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
	Path     string `json:"path"`
	Env      string `json:"env"`
	Category string `json:"category"`
}

// Manifest 是钉版清单文件。
type Manifest struct {
	Tools []Tool `json:"tools"`
}

// Load 读清单文件。
func Load(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("清单解析失败 %s: %w", path, err)
	}
	return m, nil
}

// Status 是单条工具的校验结论。
type Status string

const (
	StatusOK       Status = "ok"       // 存在且哈希匹配（或未钉版但存在）
	StatusUnpinned Status = "unpinned" // 存在但未钉版（sha256 为空）
	StatusMissing  Status = "missing"  // 找不到
	StatusMismatch Status = "mismatch" // 存在但哈希不匹配（硬失败）
)

// Result 是一条工具的校验结果。
type Result struct {
	Tool    Tool
	Status  Status
	FoundAt string // 解析到的实际路径（空 = 没找到）
	Message string
}

// Resolve 解析一条工具的实际路径：env > dataDir/path > PATH。
func Resolve(t Tool, dataDir string) string {
	if t.Env != "" {
		if v := strings.TrimSpace(os.Getenv(t.Env)); v != "" {
			return v
		}
	}
	if t.Path != "" {
		if filepath.IsAbs(t.Path) {
			return t.Path
		}
		if dataDir != "" {
			if p := filepath.Join(dataDir, t.Path); fileExists(p) {
				return p
			}
		}
		if p, err := exec.LookPath(t.Path); err == nil {
			return p
		}
		// dataDir 下的相对路径即使不存在也返回它（让 Check 报 missing 而非空路径）。
		if dataDir != "" {
			return filepath.Join(dataDir, t.Path)
		}
		return t.Path
	}
	if p, err := exec.LookPath(t.Name); err == nil {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// Check 校验清单里的每一条工具。
func Check(m Manifest, dataDir string) []Result {
	out := make([]Result, 0, len(m.Tools))
	for _, t := range m.Tools {
		at := Resolve(t, dataDir)
		if at == "" || !fileExists(at) {
			out = append(out, Result{Tool: t, Status: StatusMissing, Message: "未找到（env/PATH/data 目录均无）"})
			continue
		}
		if t.SHA256 == "" {
			out = append(out, Result{Tool: t, Status: StatusUnpinned, FoundAt: at, Message: "存在，未钉版（sha256 为空）"})
			continue
		}
		sum, err := fileSHA256(at)
		if err != nil {
			out = append(out, Result{Tool: t, Status: StatusMismatch, FoundAt: at, Message: "哈希计算失败: " + err.Error()})
			continue
		}
		if !strings.EqualFold(sum, t.SHA256) {
			out = append(out, Result{Tool: t, Status: StatusMismatch, FoundAt: at, Message: fmt.Sprintf("哈希不匹配：实际 %s，清单 %s", sum, t.SHA256)})
			continue
		}
		out = append(out, Result{Tool: t, Status: StatusOK, FoundAt: at, Message: "存在且哈希匹配"})
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ManifestPath 是 data 目录下清单的默认位置。
func ManifestPath(dataDir string) string {
	return filepath.Join(dataDir, "tools-manifest.json")
}
