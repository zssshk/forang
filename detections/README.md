# detections — 检测规则包（v0.6.6）

移植自 jiwoochris/artex-global `detections/`（AGPL-3.0），2026-11-27 取回。
FORANG 唯一改动：自更新 UA 从 `artex-selfupdate` 改为 `forang-selfupdate`
（selfupdate/github.go:98）；其余锚定字符串（富化探针 UA、平台管控标记、
CA 文件名、端口、schema 表名）均与 FORANG 源码实查一致。

## 这包是什么

防守规则，不是漏洞规则。9 条 Sigma 规则检测的是 FORANG 自身的运行指纹：

| 规则 | 信号 | 等级 |
| --- | --- | --- |
| enrich-user-agent | 富化探针 UA `artex-enrich/1.0` | high |
| selfupdate-egress | 自更新出站 UA `forang-selfupdate` | medium |
| guard-audit-framing | 平台管控审计标记（guard/guard.go） | high |
| destructive-command-hunting | 破坏性命令（与 db/db.go 内置拒单同源） | medium |
| recording-proxy-ca | 录制代理 CA 文件 `_ca/mitmproxy-ca-cert.pem` | medium |
| enrich-scan-velocity | 同源 5 分钟 ≥30 次富化探针 | high |
| enrich-fanout | 同源 10 分钟 ≥20 个不同 host | high |
| guard-block-burst | 同 host 10 分钟 ≥5 次管控标记 | high |
| guard-marker-then-destructive | 同 host 30 分钟内标记 + 破坏性命令 | high |

ATT&CK 覆盖 8 个技术（T1595/T1592/T1105/T1059/T1485/T1561.002/T1489/T1557），
编号与 `knowledge/` 的 ATT&CK 706 同源（测试断言，不另起编号）。

## 诚实口径（写进代码与文档，勿删）

- 命中只说明某 finding 的已记录证据里出现了本工具自身发出的信号，
  不是漏洞本身更严重；缺席不等于安全（静态指纹可被改掉）。
- 破坏性命令规则是通用狩猎线索，不是 FORANG 专属签名；合法管理操作会误报。
- `finding_classes` 是启发式关键词映射（类别名子串匹配），不是语义分类；
  无映射的类别在覆盖率自检里如实列为无覆盖。
- 关联规则需要真实事件时间线：登记时只跑原子规则；关联评估走任务重扫
  （已绑定流量的快照拼事件）或 `detection_check` 的 events 参数。

## 文件

- `data/rules.json`：9 条规则（内嵌，`go:embed`；`Load()` 校验重复 ID、
  关联基规则存在、token 非空）。
- `data/indicators.csv`：IoC 清单 7 行（与上游同结构，selfupdate 行已改 FORANG 值）。
- `data/indicators.misp.json`：MISP 事件（同源，供威胁情报平台导入）。
- `data/navigator_layer.json`：ATT&CK 覆盖层（8 技术，100/65/50 分制沿用上游）。
- `data/suricata.rules`：Suricata 3 条（富化 UA 现网 + 速率；norma UA 第三方）。
- `triage/forang_host_triage.py`：host triage 脚本（上游脚本改名 + selfupdate
  值适配），只读；`--self-test` 22 项全过。

## 接线

- 登记：`RecordFindingTx` 同一事务内跑原子规则，命中写 `finding_detections`
  （保存点隔离，匹配失败不影响漏洞写入）。
- 重扫：`db.RescanFindingDetections` / 工具 `detection_check` /
  `POST /api/exploration/findings/{id}/detections/rescan`。
- 开关：`detection_rules` 表（缺行 = 启用）；启动时 `NewManager` 种子。
- 导出：`GET /api/detections/ioc.csv`（finding、规则、ATT&CK、资产、证据等级）。
- 复核队列：`GET /api/detections/triage`（严重度 → 证据等级 → 命中数 → 时间）。
- 自检：`GET /api/detections/coverage`（技术维 + 类别维 + 无覆盖清单）。
- 预检：`artex doctor`（两表 + 规则包 9/5/4 计数）。
- 前端：finding 详情页「检测命中」卡片 + `/function/detections` 规则页
  （开关、覆盖率、待复核队列、制品下载）。
