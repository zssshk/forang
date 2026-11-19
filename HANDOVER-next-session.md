# 交接：FORANG/emp3r0r 融合运维 第五会话入口（2026-11-19 19:20）

> 只读本文件即可接手。历史细节、完整命令速查、更早的坑位见
> `HANDOVER-console-emp3r0r.md`（本文件不重复）。

## 〇、第四会话增量（2026-11-19 全天）：弹药库全闭环 + goc2 持久化 + DeskPilot 调查

### 1. 面板弹药库（两阶段全部上线，已真机验收）

- **三件套**（`1b8cbc7`）：`GET/POST /api/tools/c2/classic/exploits[/deploy]`
  （新文件 `server/c2_exploits.go`），前端"💣 弹药库"页签；上传核心抽成
  `c2xPushBytes()`（emp3r0r 4KB 分块 / goc2 256KB）与 files/upload 共用；
  compose 挂 `/root/poc-collection:/poc-collection:ro`（server env
  `POC_REPO` 可覆盖）。
- **选择器 v2**（`c0fc9cf`）：评分制递归扫描（3 层、跳 docs/assets/
  evidence/tests、命名评分 exploit>run.sh>*exploit*>*poc*>cve*>pwn*>ELF
  兜底、深度惩罚），覆盖 19/60→53/60；每条带 `run_hint`（README 用法行，
  执行模板预填）。剩 7 条无脚本是真没有（空目录/纯文档/Windows 驱动）。
- **PoC 库联动**（`91e7a7f`）：`GET /api/pocs` 附 `ammo` 映射（CVE→目录/
  exploit/hint，`ammoIndex()` 60s 缓存，48/2000 命中）；主面板
  `/system/pocs` 命中条目带投送按钮→弹窗选双后端会话→一键投送。
- **资产批量匹配**（`36cff4d`）：PocMatchCard——资产行手输或从资产库导入
  （api.assets），POST /pocs/match，命中行直接投送。实测 freepbx 命中
  CVE-2025-57819 带映射。
- **真机验收**：freeswitch exploit.py 8992B 3 块 28.5s 投送 emp3r0r:800bc02b
  md5 一致；mongodb poc.js 投送 + `node {name}` 执行真实回传。

### 2. goc2 修复与增强（goc2-teamserver 仓库）

- **监听器持久化**（`df52158`）：监听器原只存内存，teamserver 重启即丢
  （"无可用监听器"事故根因；beacon 不受影响——回连地址编译内嵌）。加
  `GOC2_DATA_DIR`（listeners.json 原子落盘/启动恢复），compose 挂
  `./goc2-data:/data`。当前监听器 `forang-prod`（https goc2.allclb.com:443
  → host nginx → 127.0.0.1:18400）。
- **在线统计修复**（forang `1d7effe`）：c2xStats 按 m["status"] 计数但 goc2
  Client 无 status 字段（活 beacon 被算 offline，2 显示 1）；且 c2xAgtList
  读 m["lastBeacon"] 而 goc2 字段是 last_seen（beacon 侧栏一直 unknown）。
  改按心跳时间窗判定（<300s 在线/<1800s 空闲）+ 双字段兜底 + emp3r0r 补
  lastBeacon。实测 Agents 2 / Online 2。
- **emp3r0r-cc 虚拟监听器**（`667b7c2`）：`EMP3R0R_C2_ENDPOINT`
  （compose 默认 http://158.180.91.185:13456）注入只读条目（virtual:true），
  前端生成按钮对其禁用（emp3r0r 载荷走免杀投放器）。

### 3. 部署基础设施

- **部署仓库版本化**（`2892c1e` 起）：`/root/forang-deploy` 入 git
  （origin=git@github-forang:**zssshk/forang-deploy.git** 私有）。追踪
  compose/Dockerfile/start.sh/skills/goc2 Dockerfile；.gitignore 排除
  .env、emp3r0r-bridge.env、data/、goc2-data/、dist/、goc2/ 二进制与
  payloads；模板 `.env.example`。**改 compose 后随手 commit+push**。
- **磁盘清理**：98%→82%（回收 7.7G）：build cache+悬空镜像层 2.6G、
  宿主 go-build 3.1G、apt 0.9G、/tmp 更新残留 0.9G（artex-new* 与
  poc-collection 残留 clone）、悬空匿名卷 337M（验过是 WordPress 发行版
  残留）、容器日志截断。禁清单原封：`/root/go`、`/root/android-ndk-cache`、
  `/root/.cache/qmd`、`/root/vaults`、labrats 运行容器与 labrats-lab。
- **上游检查**：F0ran9/forang 自 fork（dbe779d=v0.5.60）后 main 零更新；
  fetch 到的新 tag（v0.5.7/8/9、v0.5.55~60）是旧提交补打的标签，提交全部
  已在本地。本地领先 40 个提交。diff 用 `git diff v0.5.60..main`。

### 4. DeskPilot 目标调查（172.232.34.164）——协议级完成

**独立报告与全部证据**：`/root/dsh-workspace/deskpilot-evidence/REPORT.md`
（新会话读它接手，含下一步路线与环境说明）。要点：员工监控 C2（WS 122
操作码全功能 RAT）；`http://172.232.34.164:8080/cloud/` 分发目录零认证
（key.dat/gate.json/release.json/agent.bin + 随机名 loader 变体全取证）；
`k1sha=sha256(key.dat[:32])` 精确命中；URL 模板 `/k2/<gate>?h=<sha256>`；
反检测（Sandboxie/Cuckoo/IsDebuggerPresent）；面板 WS 认证干净。卡点：
/k2/ 全形态 404（见 REPORT.md 第八节假设排序）。Ghidra 12.2 headless 环境搭好
（/opt，aarch64 三连坑修法在 REPORT.md 第九节），capstone venv 在
/tmp/rv（重启丢失，重建两条命令）。

### 5. 实况快照（全部实测）

| 项 | 状态 |
|---|---|
| forang 仓库 | `main` @ `669a7cc`（上游 F0ran9/forang 零更新，本地领先 40），干净已推送 |
| goc2 仓库 | `main` @ `df52158`，干净已推送（监听器持久化） |
| 部署仓库 | `/root/forang-deploy` @ `268992f`，干净已推送 |
| 面板 | 8787 在跑，弹药库/PoC 联动/资产匹配全上线；**JWT 已重签**（本会话重建容器 5 次，token 均已刷新） |
| 双 C2 | goc2 `beacons=1`（会话 `sess_1_e1417884`，**goc2 重启后 ID 会变**）；emp3r0r `mcp_alive=true, active_target=800bc02b` |
| 监听器 | `forang-prod`（goc2，持久化 ✓）+ `emp3r0r-cc`（虚拟只读） |
| 验收 agent | `emp3r0r-agent.service`（cc=127.0.0.1，别覆盖） |
| SSH 别名 | `github-forang`/`github-goc2`/`github-emp3r0r`/`github-f0ran9`?（注意：forang origin 用 github-forang，上游 https 匿名拉） |
| 磁盘 | 82%（8.7G 可用）；`/root/go`、`/root/android-ndk-cache`、`/root/.cache/qmd`、`/root/vaults` **禁清**；labrats 容器在跑 |
| 定时器 | `poc-sync.timer`（每日 06:00/18:00）在跑 |

### 6. 本轮新坑（增量）

- **/tmp 重写版工具重启会丢**：`/tmp/sign_token.py`（JWT 重签，干净逻辑
  见 HANDOVER-console-emp3r0r.md 第五节但**其 heredoc 有乱码勿照抄**——
  正确版：HS256、sub=FORANG、exp=+7d、key=/tmp/jwt.key，base64url 无填充）、
  `/tmp/wstest`（node+ws）、`/tmp/rv`（capstone venv）、Ghidra 项目
  `/tmp/ghidra-proj*`——都是可快速重建的，REPORT.md 第九节有重建说明。
- **Ghidra 12.2 headless aarch64 三连坑**：①要 JDK 25（12.2 的
  application.java.min=25，apt 没有，用 Adoptium tarball）；②aarch64 包缺
  decompile 原生组件——源码自编译（去 Makefile 的 -m32、装 binutils-dev、
  修 testInstallPath 只列目录的源码 bug）；③**协议入口**：os/linux_arm_64/
  decompile 必须用 `ghidra_opt`（ghidra_process.cc），用 consolemain 版会
  与主进程协议死锁（子进程 0% CPU 假挂）。headless 项目目录必须先 mkdir。
- **伪 MZ 碰撞教训**：800K 高熵数据里找加密成功标志，"MZ in first 4K" 的
  碰撞概率 ~6%，**必须验证 MZ 偏移是否符合 PE 布局**（offset 0x1ef 的 MZ
  是噪声）。
- **pkill -f 误杀自己**：模式匹配到 bash -c 自身命令行（含 rm/cp 参数）会
  SIGKILL 自己的 shell——用 `pgrep -x <精确进程名>` 按 PID 杀。
- **agent 分钟级轮询/4KB 分块/PrivateTmp** 等旧坑依旧有效（见旧文档）。

### 7. 下一步候选

1. **DeskPilot 深挖**（REPORT.md 第八节）：监控 /cloud/ 变化抓新样本、
   Ghidra 精读 FUN_100021c0 还原完整请求头、或拿活 agent 流量。
2. 弹药库可选增强：无脚本条目的"原因说明"展示；PoC 库条目手工挂 poc_dir
   落库（当前是动态 CVE 关联）。
3. goc2 可选：监听器管理 UI（创建/删除进面板）。

## 附：高频命令（增量）

```bash
# JWT 重签（容器重建后必做；sign_token.py 若被清按第五节逻辑重写）
docker cp forang-deploy-artex-1:/app/jwt.key /tmp/jwt.key && python3 /tmp/sign_token.py
# FORANG 全链重建（Go/前端改动后）
cd /root/forang-src/web && npm run build:static && cd .. && rm -rf server/webui/dist \
  && cp -r web/out server/webui/dist \
  && PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0 GOARCH=arm64 go build -tags embedui \
     -o /root/forang-deploy/dist/arm64/artex ./cmd/artex \
  && cd /root/forang-deploy && docker compose up -d --build artex
# goc2 重编（goc2-teamserver 改动后）
cd /root/goc2-teamserver && PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0 GOARCH=arm64 \
  go build -o /root/forang-deploy/goc2/goc2-teamserver . && cd /root/forang-deploy \
  && docker compose up -d --build goc2
# 部署仓库随手提交
cd /root/forang-deploy && git add -A && git commit && git push
```

### 二、更早会话的存量工作（按 commit 回溯，详见旧文档）

1. `1ff7334` /tasks 列表接 emp3r0r 快照。2. `86b106d` PTY 结论定案（上游
缺口）。3. `f3bfca6` 插件执行+资料库取回接 emp3r0r。4. `7503c8e` OPSEC
拦截显示修复 + bridge 自愈（callToolPlain 永不重建；改 mcp.json 后必须
restart emp3r0r-bridge）。5. `244a936` schedule 三缺陷修复。6. `4f0b08b`
+`1059345` evasion-linux memfd 免杀投放器（agent 起来后自拷贝 ~/.emp3r0r
是上游固有行为）。7. `04806e1` poc-sync（README 表→PoC 库，幂等，timer
每日 06:00/18:00）。8. `ceec3cc` deploy_exploit.sh + upload 三修复
（**run_module flags 值上限 8192B，块取 4KB 原始字节**）。9. 面板密码/
Oracle 安全组 13456+27286/磁盘清理——闭环。

### 三、长期坑位速查（旧文档有完整版）

- **agent 分钟级轮询**：job 输出回传普遍 >60s，FORANG 等待窗口一律 ≥120s。
- **PrivateTmp**：agent 的 /tmp 宿主不可见，核验一律走 agent 侧命令。
- **emp3r0rRunWait 不检查退出码**：只看 output 非空，stderr 报错会被当
  成功（彻底修要 bridge 回传 rc，未做）。
- **mcp.json 权限必须 600**；改 mcp.json 后必须 restart emp3r0r-bridge。
- **容器重建后**：jwt.key 变（重签）；进程内 emp3r0r 任务快照清空（空列表
  正常）；goc2 重启后 beacon 会话 ID 会变（beacon 自动重新注册）。
