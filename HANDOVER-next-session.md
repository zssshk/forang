# 交接：FORANG/emp3r0r 融合运维 第四会话入口（2026-11-19 00:15）

> 只读本文件即可接手。历史细节、完整命令速查、更早的坑位见
> `HANDOVER-console-emp3r0r.md`（本文件不重复）。

## 〇、第四会话增量（2026-11-18 22:04~00:10）：面板弹药库已上线

第三会话规划的"弹药库三件套"已完成并真机验收（`1b8cbc7` + `c0fc9cf`，已推送）：

1. **compose 挂载**：`/root/forang-deploy/docker-compose.override.yml` artex.volumes
   加 `- /root/poc-collection:/poc-collection:ro`（server 端 `POC_REPO` env 可覆盖，
   默认 `/poc-collection`；宿主跑测试用 `POC_REPO=/root/poc-collection`）。
2. **后端**（新文件 `server/c2_exploits.go` + `c2_classic.go` 抽取重构）：
   - `GET /api/tools/c2/classic/exploits`：解析仓库 README 表格（移植
     `poc-sync/import_pocs.py`），**评分制选主 exploit**（递归 3 层、命名评分
     exploit>run.sh>*exploit*>*poc*>cve*>pwn*>ELF 兜底、深度惩罚、跳过
     docs/assets/evidence/tests），覆盖率 53/60（首轮窄规则只有 19/60）；
     每条带 `run_hint`（README 用法行，预填执行模板）；
   - `POST /api/tools/c2/classic/exploits/deploy`：`{agent_id, poc_dir, run_cmd?}`
     → 主 exploit 投送到 `/tmp/__poc/`（路径校验防越界）+ 可选 `{name}` 模板
     执行（与 command 端点同路：非阻塞 enqueue，回 command_id）；
   - `c2_classic.go` 的上传核心抽成 `c2xPushBytes(ctx, agent, dest, filename,
     data)`，files/upload 与弹药库投送共用（emp3r0r 4KB 分块 / goc2 256KB）。
   - 剩 7 条无脚本为真没有（5 空目录、dokploy 仅 README、vuln-driver-mapper
     是 Windows 驱动工程），NONE 显示是诚实的。
3. **前端**：`index.html` 加"💣 弹药库"页签（plugins 后）+ `panel-exploits`；
   `app.js` 加 `exploitsRefresh/exploitsRender/exploitDeploy/exploitRun`，
   switchTab 与 agent 指示器已挂钩，带 CVE/组件/严重度过滤，执行按钮
   预填 run_hint。
4. **真机验收**：freeswitch exploit.py（8992B，3 块 28.5s，agent md5 一致）+
   mongodb poc.js（2 块 + `node {name}` 执行真实回传，报缺 mongodb 模块属
   目标机环境差异）。容器已重建、JWT 已重签。
5. 部署侧坑：`dist/arm64/artex` 是宿主 `CGO_ENABLED=0 GOARCH=arm64
   go build -tags embedui` 产物（go 在 `/usr/local/go/bin`）；`/tmp/sign_token.py`
   已重写（旧文档第五节 heredoc 有乱码，勿照抄），干净版在 /tmp。

**第二阶段未动工**（下会话可接）：PoC 库 2000+ 条目与弹药库联动——条目挂
poc_dir、资产匹配命中后一键投送。


## 一、实况快照（全部实测）

| 项 | 状态 |
|---|---|
| forang 仓库 | `main` @ `38f2079`，origin=`git@github-forang:zssshk/forang.git`，干净已推送 |
| emp3r0r 仓库 | `v5` @ `995c467b`，origin=`git@github-emp3r0r:...`，干净 |
| goc2 仓库 | `main` @ `3f340c7`，origin=`git@github-goc2:...`，干净 |
| 面板 | docker compose `forang-deploy/artex`，127.0.0.1:8787 / forang.allclb.com，**密码已初始化** |
| 双 C2 | goc2 `beacons=1`；emp3r0r `mcp_alive=true, active_target=800bc02b` |
| 验收 agent | `emp3r0r-agent.service`（cc=127.0.0.1，别覆盖），goc2 `sess_1_44eb6bc2` |
| SSH 别名 | `github-forang`/`github-goc2`/`github-emp3r0r` 各自独立（`Host github.com` 是 hghub 的 key，勿动）；git 全局身份已配（FORANG operator） |
| 磁盘 | 90%（4.9G 可用）；`/root/go` 是容器免杀 GOROOT 挂载、`/root/android-ndk-cache` 是 ghostlock 构建链、`/root/.cache/qmd` 是检索模型——**都别清** |
| 定时器 | `poc-sync.timer`（每日 06:00/18:00）已在跑 |

## 二、本会话完成的全部工作（按 commit 回溯）

1. `1ff7334` `/tasks` 列表查询接 emp3r0r 快照（原先报"会话不存在"）。
2. `86b106d` **PTY 结论定案**：缺口在 emp3r0r 上游（Operation 无 stdin、
   job 只追加、Foreground 未实现、creack/pty 零 import），不是 bridge 补端点
   能解决的。501+原因（c2_classic2.go:33）是正确的边界表达。
3. `f3bfca6` 插件执行 + 资料库取回接 emp3r0r（`c2RunTaskWait` 只认 goc2、
   `upload <path>` 取回分支绕过前缀判断——都已分流）。
4. `7503c8e` **OPSEC 拦截不再显示为成功**：`emp3r0rBlocked` 解析
   `blocked/executed:false/decision.allowed:false`；建
   `/root/.emp3r0r/mcp.json`（600，allow_irreversible:true，保留 max_noise
   与 30/min 限速）——没这文件时默认策略连 `rm`/`crontab -l` 都拒。
   **bridge 自愈修复**：`read_job_output` 的 miss 是常态（agent 分钟级
   poll），原 callTool 每次失败就杀 mcp 重建（实测 8 秒 5 次），现走
   `callToolPlain` 永不重建。**改 mcp.json 后必须 restart emp3r0r-bridge**。
5. `244a936` schedule 三缺陷修复：add 的 grep -v 会清空标记族、rm 按全量
   行号删（实测删过用户 kejilion 任务）、生成命令用了 bash `<(...)` 而
   run_module 跑 dash。现为幂等 add + 标记序号精确删 + mktemp 纯 sh。
   四子命令真机端到端验证过；用户 crontab 完好。
6. `4f0b08b`+`1059345` **evasion-linux memfd 免杀投放器**：stager 链
   arm64 不可用（malasada PIC 仅 amd64 + stub.c 按函数指针跳转只认 PIC），
   FORANG 侧自建 loader（zlib+AES-CTR+go:embed → memfd_create syscall 279
   不设 CLOEXEC → execve /proc/self/fd/N）。7.5MB loader 内嵌 16.2MB
   TLS agent，实测 memfd 执行、TLS 上线、磁盘零落盘。**边界**：agent
   起来后自拷贝到 ~/.emp3r0r 是上游固有行为。出货流程见旧文档新增节。
7. `04806e1` **poc-sync**：zssshk/poc-collection（private，SSH key 可达）
   → git pull → 解析 README 表 → 幂等导入 PoC 库（按 CVE 去重，CVSS 映射
   severity）。首跑导入 50，复跑 0 导入。systemd timer 每日 06:00/18:00。
8. `ceec3cc` **exploit 投送 + upload 三修复**：`poc-sync/deploy_exploit.sh
   <poc-dir> <agent_id> [--run "模板"]` 一键投送+可选执行。修掉 upload
   两个硬 bug：run_module flags 值上限 **8192B**（256KB 的 goc2 粒度完全
   不可用，实测 5.5KB 过/8KB 拒 → 块改 4KB）；emp3r0r 分支不 mkdir -p；
   等待窗口 60→120s。9.5KB exploit 三块送达，agent 侧 md5 与仓库一致。
9. 面板密码（YG 已设）、Oracle 安全组 13456/27286（已放行，实测公网可达）、
   磁盘清理（悬空镜像 1.7G + build cache 1.3G + /tmp）——全部闭环。

## 三、下一步：PoC 库条目与弹药库联动（第二阶段，未动工）

弹药库三件套第四会话已完成并验收（见"〇"节），宿主命令行的
`deploy_exploit.sh` 仍可用。下一阶段方向（第三会话已确认）：

PoC 库条目（FORANG 面板 /api/pocs，已 2000+ 条）与弹药库联动：条目挂
poc_dir，资产匹配命中后一键投送。改动点在面板 PoC 库页 + 资产匹配逻辑，
弹药库端点（exploits/deploy）已就绪可直接复用。

## 四、高频命令（只列新增；其余见旧文档）

```bash
# 弹药投送（宿主）
/root/forang-src/poc-sync/deploy_exploit.sh <poc-dir> emp3r0r:<tag> [--run "..."]
# 手动同步 PoC 库
/root/forang-src/poc-sync/poc-sync.sh && journalctl -u poc-sync -n 5
# JWT 重签（容器重建后必做）
docker cp forang-deploy-artex-1:/app/jwt.key /tmp/jwt.key && python3 /tmp/sign_token.py
```
（/tmp/sign_token.py 若被清，重写逻辑：HS256，sub=FORANG，exp=+7d，
key=/tmp/jwt.key——旧文档第五节有完整版。）

## 五、本轮新坑（旧文档坑位的增量）

- **run_module flags 值上限 8192B**——所有走 bridge 的命令体都受此约束，
  任何"往命令里塞大 payload"的方案（上传、stager 参数）都要按 4KB 原始
  字节/块设计。
- **agent 分钟级轮询**：job 输出回传普遍 >60s，FORANG 侧等待窗口一律
  ≥120s；验证"没执行"先等 2 分钟再下结论。
- **PrivateTmp**：agent 的 /tmp 是私有的，宿主 ls 看不到；核验文件一律
  用 agent 侧命令（md5sum/ls 经 bridge）。
- **emp3r0rRunWait 不检查命令退出码**：只看 output 非空——sh 的 stderr
  报错会被当成"成功"。当前靠调用方（mkdir 修好）规避，彻底修要 bridge
  回传 rc（未做）。
- **mcp.json 权限必须 600**：组/全局可写会让 MCP 拒绝启动。
- **容器重建后**：jwt.key 变 → 重签；进程内 emp3r0r 任务快照清空（空列表
  是正常现象，不是 bug）；agent 会话不受影响。
