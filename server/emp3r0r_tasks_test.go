package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// seedEmp3r0rTask 往进程内任务表塞一条记录，返回清理函数。
func seedEmp3r0rTask(t *testing.T, id, clientID, cmd, status, output string) {
	t.Helper()
	tsk := &emp3r0rTask{
		ID:        id,
		ClientID:  clientID,
		Type:      "exec",
		Args:      map[string]any{"cmd": cmd},
		Status:    status,
		Output:    output,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	emp3r0rTasks.Store(id, tsk)
	t.Cleanup(func() { emp3r0rTasks.Delete(id) })
}

// 会话过滤必须精确：别的会话的同名任务不能串进来，也不能漏掉本会话。
func TestEmp3r0rTasksForClientFiltersBySession(t *testing.T) {
	seedEmp3r0rTask(t, "emp3r0r_task_9001", "emp3r0r:aaa", "id", "done", "uid=0(root)")
	seedEmp3r0rTask(t, "emp3r0r_task_9002", "emp3r0r:aaa", "hostname", "done", "box")
	seedEmp3r0rTask(t, "emp3r0r_task_9003", "emp3r0r:bbb", "id", "done", "uid=1000(x)")

	got := emp3r0rTasksForClient("emp3r0r:aaa")
	if len(got) != 2 {
		t.Fatalf("emp3r0r:aaa 应有 2 条任务，实得 %d：%#v", len(got), got)
	}
	for _, row := range got {
		m, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("行不是 map：%T", row)
		}
		if cid, _ := m["client_id"].(string); cid != "emp3r0r:aaa" {
			t.Fatalf("混入了别的会话：%v", cid)
		}
	}

	// 匿名会话返回全部（SSE poller 依赖此行为）
	if all := emp3r0rTasksForClient(""); len(all) < 3 {
		t.Fatalf("全量快照应 >=3 条，实得 %d", len(all))
	}
	if all := emp3r0rAllTasks(); len(all) < 3 {
		t.Fatalf("emp3r0rAllTasks 应 >=3 条，实得 %d", len(all))
	}
}

// 行形状必须与单任务视图同构：c2classic 断言 createdAt 为 string，
// 且需要 output/args/status 四个键才画得出命令历史。
func TestEmp3r0rTasksForClientShapeMatchesTaskView(t *testing.T) {
	seedEmp3r0rTask(t, "emp3r0r_task_9010", "emp3r0r:ccc", "uname -a", "done", "Linux box")

	rows := emp3r0rTasksForClient("emp3r0r:ccc")
	if len(rows) != 1 {
		t.Fatalf("应有 1 条，实得 %d", len(rows))
	}
	row, _ := rows[0].(map[string]any)
	if row == nil {
		t.Fatal("行不是 map")
	}
	inView := emp3r0rTaskView("emp3r0r_task_9010")
	viewRows, _ := inView["data"].([]any)
	if len(viewRows) != 1 {
		t.Fatalf("任务视图应有 1 条，实得 %d", len(viewRows))
	}
	raw, _ := json.Marshal(viewRows[0])
	viewRow := map[string]any{}
	_ = json.Unmarshal(raw, &viewRow)
	// 视图侧额外带 result（与 output 同值），列表侧刻意去掉；其余键必须同集同值。
	delete(viewRow, "result")

	if len(row) != len(viewRow) {
		t.Fatalf("列表行与单任务视图键集不一致：列表 %v / 视图 %v", keysOf(row), keysOf(viewRow))
	}
	for k, want := range viewRow {
		got, ok := row[k]
		if !ok {
			t.Fatalf("列表行缺少键 %q（视图有：%v）", k, keysOf(viewRow))
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("键 %q 不一致：列表 %s / 视图 %s", k, gotJSON, wantJSON)
		}
	}
	if _, ok := row["createdAt"].(string); !ok {
		t.Fatalf("createdAt 必须是 string（c2classic 用类型断言读），实为 %T", row["createdAt"])
	}
}

// session_id 带 emp3r0r 前缀的列表查询必须走快照，不能落到 goc2 报「会话不存在」。
func TestC2TasksAPIEmp3r0rSessionListDoesNotHitGoc2(t *testing.T) {
	prevBridge := emp3r0rBridge
	emp3r0rBridge = "http://127.0.0.1:1" // 不可达：一旦走 goc2 就会 502 而非 200
	t.Cleanup(func() { emp3r0rBridge = prevBridge })

	seedEmp3r0rTask(t, "emp3r0r_task_9020", "emp3r0r:ddd", "whoami", "done", "root")

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/c2/tasks?session_id=emp3r0r:ddd", nil)
	rec := httptest.NewRecorder()
	s.c2TasksAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实得 %d：%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 {data:[...]}：%v / %s", err, rec.Body.String())
	}
	if len(out.Data) != 1 {
		t.Fatalf("期望 1 条任务，实得 %d：%s", len(out.Data), rec.Body.String())
	}
	if got, _ := out.Data[0]["output"].(string); got != "root" {
		t.Fatalf("output 不符：%q", got)
	}
}

// 非 emp3r0r 会话不得被新分支截走（仍要尝试 goc2）。
func TestC2TasksAPIGoc2SessionStillRoutedToGoc2(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/tools/c2/tasks?session_id=sess_nonexistent&task_id=emp3r0r_task_nope", nil)
	rec := httptest.NewRecorder()
	s.c2TasksAPI(rec, req)
	// 纯 emp3r0r 前缀 task_id 查不到 → 404，证明前缀路由仍先于会话路由生效。
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 emp3r0r 任务应 404，实得 %d：%s", rec.Code, rec.Body.String())
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// OPSEC 拦截必须被识别为失败，不能当成正常回显——bridge 对拦截也回 200，
// 漏判会让面板把「目标机上什么都没执行」显示成「已完成」。
func TestEmp3r0rBlockedDetectsInterception(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		blocked bool
	}{
		{"rm 拦截", `{"blocked":true,"command":"exec --cmd 'rm -rf /tmp/x'","decision":{"allowed":false,"reason":"action is irreversible; set allow_irreversible to permit it"},"executed":false,"reason":"action is irreversible; set allow_irreversible to permit it"}`, true},
		{"只有 executed:false", `{"executed":false,"module":"exec","reason":"no active target"}`, true},
		{"只有 decision.allowed:false", `{"decision":{"allowed":false,"reason":"denied by policy"}}`, true},
		{"正常回显", "uid=0(root) gid=0(root)\n", false},
		{"正常 JSON 回显", `{"executed":true,"job_id":"abc"}`, false},
		{"base64 文本（非 JSON）", "cHJvYmUtcGF5bG9hZA==\n", false},
		{"空输出", "", false},
	}
	for _, c := range cases {
		got, reason := emp3r0rBlocked(c.output)
		if got != c.blocked {
			t.Fatalf("%s: blocked=%v 期望 %v（reason=%q）", c.name, got, c.blocked, reason)
		}
		if got && reason == "" {
			t.Fatalf("%s: 拦截必须带原因", c.name)
		}
	}
}
