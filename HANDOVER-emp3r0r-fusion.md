# 交接：FORANG 双 C2 融合（goc2 + emp3r0r）与全套能力落地（2026-11-17 21:00）

> 接 `HANDOVER-beacon-agent.md`（goc2 agent/generate 已完成验收）。本文件交接本会话的
> 三大块工作：① goc2 真实 agent + 载荷生成（v0.3.0/0.3.1，已验收）；② FORANG 深读与
> 免杀强化（t1/t3，已推送）；③ **面板融合 emp3r0r（架构与代码全部就位，差最后一轮
> 端到端收尾——见"遗留"）**。接手方从本文件开始，不用重读旧会话。

## 一、部署现状（DSH 158.180.91.185，本机即部署机）

| 组件 | 位置/端口 | 状态 |
|---|---|---|
| goc2 v0.3.0 容器 | `/root/forang-deploy/`，127.0.0.1:18400 | ✅ 验收通过（agent/PTY/generate） |
| FORANG 面板容器 | 127.0.0.1:8787，nginx forang.allclb.com:443 | ✅ 验收通过 |
| 生产 beacon agent | systemd `goc2-agent.service`，连 18400 | ✅ 在线（sess_1_478aa5b4） |
| goc2 回连域名 | https://goc2.allclb.com（LE 证书，nginx 白名单） | ✅ 目标机视角实测 |
| FORANG MCP | `/usr/local/bin/forang-mcp`（stdio，13 工具） | ✅ 实测（OPSEC 闸+审计） |
| emp3r0r server | `/usr/local/bin/emp3r0r`，C2 HTTP 13456 + WG 面 13377/13378 | ✅ 运行中（nohup，未 systemd） |
| emp3r0r-bridge | `/usr/local/bin/emp3r0r-bridge`，systemd，172.17.0.1:18660 | ✅ 运行中（mcp_alive=true） |
| emp3r0r agent payload | /tmp/agent-test（手动编译，带 MagicString） | ⚠️ 进程活着但 server 未见其连接 |

关键凭据/配置：
- bridge token：`/root/forang-deploy/emp3r0r-bridge.env` 与 `.env` 的 `EMP3R0R_BRIDGE_TOKEN`（同值）
- WG operator 凭据：`/root/.emp3r0r/wg_config.json`（bridge 自动读取构造 mcp 参数）
- FORANG JWT：容器内 `/app/jwt.key`（容器重建会变，用 docker cp 取）
- FORANG MCP 审计：`~/.forang-mcp/audit.jsonl`

## 二、三大块工作

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

### 3. 面板融合 emp3r0r（FORANG 提交 b4297c8 + 本地未推送的 bridge 修改）
- 架构：FORANG 容器不持 WG 凭据；宿主机 `emp3r0r-bridge`（持凭据 + spawn
  `emp3r0r mcp`）暴露 token 保护的 localhost REST；FORANG `server/emp3r0r.go`
  适配层经 bridge 操作；会话 id `emp3r0r:` 前缀命名空间，c2_api.go 按前缀路由
- FORANG 侧已验证：/status 融合字段 `emp3r0r:{reachable,mcp_alive}` 生效
- MCP 协议直调验证通过：initialize + list_agents（新进程瞬时返回）
- bridge 自愈：工具调用失败/超时 → kill 重建 mcp → 重试一次（已部署）

## 三、遗留（接手按序做）

1. **bridge 长驻 mcp 的 list_agents 挂起**：FORANG 容器重启期间 operator tunnel
   被 C2 替换（"replaced the previous tunnel"），旧 mcp 连接进黑洞，工具调用超时。
   自愈逻辑已写（callTool 失败→rebuild→重试），但 list_agents 60s 超时 + 重建 +
   重试的端到端路径未验证。排查入口：journalctl -u emp3r0r-bridge、
   /tmp/emp3r0r-mcp.stderr、~/.emp3r0r/emp3r0r.log。注意：新 spawn 的 mcp 进程
   实例一切正常（Python subprocess 直调 0.0s 返回）——问题只在长连接失效场景。
2. **emp3r0r agent 上线**：手动 go build ./cmd/agent 的裸二进制报 config slot
   错误（"length 4294967295 exceeds slot of 4096"）——必须用 build.py 生成
   （ldflags 注入 config）。`python3 build.py --build-payload --payload-kind pure
   --payload-os linux --payload-arch arm64 --payload-output <path>
   --payload-magic-string <server 的 MagicString，见 server 日志>` 失败原因未定位
   （同命令手动编译成功，build.py 自身检查问题——完整跑一遍看尾部输出）。
   agent 上线后：FORANG /clients 应出现 emp3r0r: 前缀目标 → /exec 走 run_module
   exec（BOF 经 coffloader）→ 面板双后端同屏验收完成。
3. **emp3r0r server 未 systemd 化**：现在 nohup 跑着（/tmp/emp3r0r-server.log），
   重启会丢。写 emp3r0r-server.service（ExecStart 参见 ps 或 server --help）。
4. 构建链备注：emp3r0r-builder 镜像是 amd64（manylinux2014 硬编码），ARM 宿主
   qemu 模拟慢 10 倍——arm64 产物在宿主机直编（zig 已装 /opt/zig-arm64，
   exec.o/coffloader_linux.so 已编好放进 /usr/local/lib/emp3r0r/modules/）；
   modules 目录还缺其它模块产物（v1 只装了 exec+coffloader）。

## 四、命令速查

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
# emp3r0r server / agent
tail -5 /tmp/emp3r0r-server.log; ps aux | grep -E "emp3r0r server|agent-test" | grep -v grep
# goc2 agent
systemctl status goc2-agent; curl -s http://127.0.0.1:18400/healthz
# 仓库
git -C /root/goc2-teamserver log --oneline -3   # v0.3.1=3f340c7
git -C /root/forang-src log --oneline -3        # fusion=b4297c8（bridge 自愈改动在本地未提交，见下）
```

**未提交改动**：`cmd/emp3r0r-bridge/main.go` 的 WG 自动参数 + 自愈逻辑（mcpArgs/
callTool/rebuild）与 mcp stderr 诊断落盘改动在本地已编译部署但未 commit——接手
先 `git -C /root/forang-src diff cmd/emp3r0r-bridge/` 确认后提交推送。

## 五、验收标准（收尾完成即达标）

- FORANG /clients 同时显示 goc2 beacon（sess_1_478aa5b4）与 emp3r0r 目标（emp3r0r: 前缀）
- FORANG /api/tools/c2/exec 对 emp3r0r 目标下发命令，run_module exec 经 coffloader
  内存加载返回输出，c2classic 控制台 SSE 能推送该结果
- bridge 自愈验证：kill mcp 子进程 → 下一次工具调用自动重建成功
- FORANG 面板 status 双后端 reachable=true 持续稳定（operator tunnel 无黑洞）
