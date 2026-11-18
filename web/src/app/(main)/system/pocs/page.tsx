"use client";

// POC 闭环管理：POC 库（nuclei 模板）列表 / 新建 / 编辑 / 删除 / 单目标验证。
// agent 侧对应 match_poc / run_poc_verify / save_poc 工具，共用同一张表。
import * as React from "react";

import { FlaskConicalIcon, PlayIcon, PlusIcon, RefreshCwIcon, RocketIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { PocSourcesCard } from "./_components/poc-sources-card";

interface Poc {
  id: number;
  title: string;
  component: string;
  cve: string;
  severity: string;
  template: string;
  source: string;
  verified: boolean;
  last_target: string;
  last_result: string;
}

interface AmmoInfo {
  dir: string;
  exploit: string;
  hint: string;
}

interface C2Client {
  id: string;
  hostname?: string;
  ip?: string;
  os?: string;
  username?: string;
}

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export default function PocsPage() {
  const [pocs, setPocs] = React.useState<Poc[]>([]);
  const [ammo, setAmmo] = React.useState<Record<string, AmmoInfo>>({});
  const [editing, setEditing] = React.useState<Poc | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [verifyTarget, setVerifyTarget] = React.useState<Record<number, string>>({});
  const [verifying, setVerifying] = React.useState<number | null>(null);
  // 弹药联动：选中的 POC / 会话列表 / 执行模板 / 投送状态
  const [deployPoc, setDeployPoc] = React.useState<Poc | null>(null);
  const [deployAmmo, setDeployAmmo] = React.useState<AmmoInfo | null>(null);
  const [deployAgents, setDeployAgents] = React.useState<C2Client[]>([]);
  const [deployAgent, setDeployAgent] = React.useState("");
  const [deployCmd, setDeployCmd] = React.useState("");
  const [deployBusy, setDeployBusy] = React.useState(false);
  const [deployResult, setDeployResult] = React.useState("");

  const load = React.useCallback(() => {
    api
      .pocList()
      .then((r) => {
        setPocs((r.pocs ?? []) as Poc[]);
        setAmmo(r.ammo ?? {});
      })
      .catch((e) => toast.error(`加载 POC 失败：${e.message}`));
  }, []);

  // openDeploy 打开投送弹窗：拉双后端会话列表，预填 README 用法模板
  // （脚本名 → {name} 占位）。
  const openDeploy = React.useCallback(
    (p: Poc) => {
      const a = ammo[p.cve];
      if (!a) return;
      setDeployPoc(p);
      setDeployAmmo(a);
      setDeployResult("");
      const base = (a.exploit.split("/").pop() || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const hint = a.hint || `python3 ${a.exploit}`;
      setDeployCmd(base ? hint.replace(new RegExp(base, "g"), "{name}") : hint);
      api
        .c2Clients()
        .then((r) => {
          const list = ((r.data ?? []) as unknown as C2Client[]).filter((c) => c.id);
          setDeployAgents(list);
          if (list.length) setDeployAgent(list[0].id);
        })
        .catch((e) => toast.error(`拉取会话失败：${e.message}`));
    },
    [ammo],
  );

  const doDeploy = React.useCallback(() => {
    if (!deployPoc || !deployAmmo || !deployAgent) {
      toast.warning("请选择目标会话");
      return;
    }
    setDeployBusy(true);
    setDeployResult("[*] 投送中（emp3r0r 会话按 4KB 分块，可能需要 1~2 分钟）…");
    api
      .pocDeploy(deployAgent, deployAmmo.dir, deployCmd.trim() || undefined)
      .then((r) => {
        let t = `[+] ${r.poc_dir}/${r.exploit} → ${r.remote_path}（${r.total} 块）`;
        if (r.command_id) t += `\n[+] 执行已下发（command_id=${r.command_id}）\n[*] agent 分钟级轮询，输出稍后在 C2 终端页查看`;
        if (r.run_error) t += `\n[!] 执行下发失败: ${r.run_error}`;
        setDeployResult(t);
        toast.success("投送完成");
      })
      .catch((e) => setDeployResult(`[!] 投送失败: ${e.message}`))
      .finally(() => setDeployBusy(false));
  }, [deployPoc, deployAmmo, deployAgent, deployCmd]);

  React.useEffect(() => {
    load();
  }, [load]);

  const verify = React.useCallback(
    (id: number) => {
      const target = (verifyTarget[id] || "").trim();
      if (!target) {
        toast.warning("请先填目标 URL");
        return;
      }
      setVerifying(id);
      api
        .pocVerify(id, target)
        .then((r) => {
          if (r.matched) toast.success(`命中！${(r.result || "").slice(0, 120)}`);
          else toast.info(`未命中：${(r.result || "").slice(0, 120)}`);
          load();
        })
        .catch((e) => toast.error(`验证失败：${e.message}`))
        .finally(() => setVerifying(null));
    },
    [verifyTarget, load],
  );

  return (
    <div className="flex min-w-0 flex-1 flex-col p-4 sm:p-6">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="font-semibold text-xl">POC 闭环</h1>
          <p className="text-muted-foreground text-sm">
            POC 库（nuclei 模板 + 指纹关键字）→ 批量匹配 → 精确验证 → 验证成功才入库。
            agent 侧通过 match_poc / run_poc_verify / save_poc 复用同一份数据。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCwIcon className="size-4" /> 刷新
          </Button>
          <Button size="sm" onClick={() => setCreating((v) => !v)}>
            <PlusIcon className="size-4" /> 新建 POC
          </Button>
        </div>
      </div>
      <PocSourcesCard onChanged={load} />

      <PocMatchCard ammo={ammo} onDeploy={openDeploy} />

      {(creating || editing) && (
        <PocEditor
          initial={editing}
          onDone={() => {
            setCreating(false);
            setEditing(null);
            load();
          }}
          onCancel={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            <FlaskConicalIcon className="mr-1 inline size-4" /> POC 库（{pocs.length}）
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>标题</TableHead>
                <TableHead>指纹关键字</TableHead>
                <TableHead>CVE</TableHead>
                <TableHead>等级</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>最近验证</TableHead>
                <TableHead className="w-[280px]">验证</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {pocs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-muted-foreground text-center">
                    POC 库为空。手动新建，或在渗透任务里让 agent 验证成功后自动入库（save_poc）。
                  </TableCell>
                </TableRow>
              ) : (
                pocs.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="max-w-[220px] truncate font-medium">
                      {p.title}
                      {p.verified ? (
                        <Badge className="ml-1" variant="default">
                          已验证
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{p.component}</TableCell>
                    <TableCell className="font-mono text-xs">{p.cve || "-"}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{p.severity || "info"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={p.source === "ai" ? "secondary" : "outline"}>{p.source}</Badge>
                    </TableCell>
                    <TableCell className="max-w-[180px] truncate text-xs">
                      {p.last_result ? `${p.last_target}：${p.last_result}` : "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Input
                          className="h-7 w-40 text-xs"
                          placeholder="https://target"
                          value={verifyTarget[p.id] || ""}
                          onChange={(e) => setVerifyTarget((m) => ({ ...m, [p.id]: e.target.value }))}
                        />
                        <Button size="sm" variant="outline" disabled={verifying === p.id} onClick={() => verify(p.id)}>
                          <PlayIcon className="size-3.5" />
                          {verifying === p.id ? "验证中…" : "验证"}
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        {p.cve && ammo[p.cve] ? (
                          <Button size="sm" variant="outline" onClick={() => openDeploy(p)} title={`${ammo[p.cve].dir}/${ammo[p.cve].exploit}`}>
                            <RocketIcon className="size-4" /> 投送
                          </Button>
                        ) : null}
                        <Button size="sm" variant="ghost" onClick={() => setEditing(p)}>
                          编辑
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            if (!confirm(`删除 POC「${p.title}」？`)) return;
                            api
                              .pocDelete(p.id)
                              .then(load)
                              .catch((e) => toast.error(`删除失败：${e.message}`));
                          }}
                        >
                          <Trash2Icon className="size-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={!!deployPoc} onOpenChange={(v) => !v && setDeployPoc(null)}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle>弹药投送{deployPoc ? ` · ${deployPoc.cve || deployPoc.title}` : ""}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            {deployAmmo ? (
              <div className="text-muted-foreground text-xs">
                弹药：{deployAmmo.dir}/{deployAmmo.exploit || "（无主 exploit，仅投送不可用）"}
              </div>
            ) : null}
            <div className="space-y-1">
              <Label>目标会话</Label>
              <Select value={deployAgent} onValueChange={setDeployAgent}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder={deployAgents.length ? "选择会话" : "无在线会话"} />
                </SelectTrigger>
                <SelectContent>
                  {deployAgents.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.hostname || c.id} · {c.ip || "?"} · {c.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>执行命令模板（{`{name}`} = 远端文件路径，留空只投送）</Label>
              <Input className="font-mono text-xs" value={deployCmd} onChange={(e) => setDeployCmd(e.target.value)} placeholder="python3 {name} --target http://x" />
            </div>
            {deployResult ? <pre className="max-h-48 overflow-auto rounded border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap">{deployResult}</pre> : null}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeployPoc(null)}>
              关闭
            </Button>
            <Button disabled={deployBusy || !deployAmmo?.exploit || !deployAgent} onClick={doDeploy}>
              <RocketIcon className="size-4" /> {deployBusy ? "投送中…" : "投送"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface PocMatchRow {
  target: string;
  reason: string;
  poc: Poc;
}

// PocMatchCard 资产批量匹配：手输或从资产库导入 {target,component} 行，
// POST /pocs/match 后命中行可一键投送（弹药目录命中的 CVE）。
function PocMatchCard({
  ammo,
  onDeploy,
}: {
  ammo: Record<string, AmmoInfo>;
  onDeploy: (p: Poc) => void;
}) {
  const [input, setInput] = React.useState("");
  const [matches, setMatches] = React.useState<PocMatchRow[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [importing, setImporting] = React.useState(false);

  const importAssets = React.useCallback(() => {
    setImporting(true);
    api
      .assets("all", 200)
      .then((r) => {
        const rows = (r.assets ?? []).map((a) => {
          const target = a.domain || (a.ip ? a.ip + (a.port ? `:${a.port}` : "") : "");
          const component =
            a.bound_domains?.join(",") ||
            a.open_ports?.map((p) => p.service).filter(Boolean).join(",") ||
            "";
          return target ? `${target},${component}` : "";
        }).filter(Boolean);
        if (!rows.length) {
          toast.info("资产库为空或无可导出条目");
          return;
        }
        setInput((prev) => (prev ? prev + "\n" : "") + rows.join("\n"));
        toast.success(`已导入 ${rows.length} 条资产`);
      })
      .catch((e) => toast.error(`拉取资产失败：${e.message}`))
      .finally(() => setImporting(false));
  }, []);

  const runMatch = React.useCallback(() => {
    const assets = input
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [target, ...rest] = l.split(",");
        return { target: (target || "").trim(), component: rest.join(",").trim() };
      })
      .filter((a) => a.target);
    if (!assets.length) {
      toast.warning("请先填资产行（target,component）");
      return;
    }
    setBusy(true);
    api
      .pocMatch(assets)
      .then((r) => {
        setMatches((r.matches ?? []) as PocMatchRow[]);
        toast.info(`命中 ${(r.matches ?? []).length} 条`);
      })
      .catch((e) => toast.error(`匹配失败：${e.message}`))
      .finally(() => setBusy(false));
  }, [input]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">资产批量匹配 → 弹药投送</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label>资产行（每行 target,component；component 为指纹关键字）</Label>
            <Button size="sm" variant="outline" disabled={importing} onClick={importAssets}>
              {importing ? "导入中…" : "从资产库导入"}
            </Button>
          </div>
          <Textarea
            rows={4}
            className="font-mono text-xs"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={"http://10.0.0.5:8080,若依,ruoyi\nvpn.corp.com,freepbx"}
          />
        </div>
        <Button size="sm" disabled={busy} onClick={runMatch}>
          {busy ? "匹配中…" : "批量匹配"}
        </Button>
        {matches.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>目标</TableHead>
                <TableHead>POC</TableHead>
                <TableHead>CVE</TableHead>
                <TableHead>等级</TableHead>
                <TableHead>命中</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {matches.slice(0, 100).map((m, i) => {
                const a = m.poc.cve ? ammo[m.poc.cve.toUpperCase()] : undefined;
                return (
                  <TableRow key={`${m.target}-${m.poc.id}-${i}`}>
                    <TableCell className="font-mono text-xs">{m.target}</TableCell>
                    <TableCell className="max-w-[220px] truncate text-xs">{m.poc.title}</TableCell>
                    <TableCell className="font-mono text-xs">{m.poc.cve || "-"}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{m.poc.severity || "info"}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{m.reason}</TableCell>
                    <TableCell className="text-right">
                      {a ? (
                        <Button size="sm" variant="outline" onClick={() => onDeploy(m.poc)}>
                          <RocketIcon className="size-4" /> 投送
                        </Button>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        ) : null}
      </CardContent>
    </Card>
  );
}

function PocEditor({
  initial,
  onDone,
  onCancel,
}: {
  initial: Poc | null;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [title, setTitle] = React.useState(initial?.title || "");
  const [component, setComponent] = React.useState(initial?.component || "");
  const [cve, setCve] = React.useState(initial?.cve || "");
  const [severity, setSeverity] = React.useState(initial?.severity || "info");
  const [template, setTemplate] = React.useState(initial?.template || "");
  const [busy, setBusy] = React.useState(false);

  return (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="text-base">{initial ? `编辑 POC #${initial.id}` : "新建 POC"}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-4">
          <div className="space-y-1">
            <Label>标题</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="RuoYi 默认口令探测" />
          </div>
          <div className="space-y-1">
            <Label>指纹关键字（逗号分隔）</Label>
            <Input value={component} onChange={(e) => setComponent(e.target.value)} placeholder="ruoyi,若依" />
          </div>
          <div className="space-y-1">
            <Label>CVE（可空）</Label>
            <Input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2023-27025" />
          </div>
          <div className="space-y-1">
            <Label>等级</Label>
            <div className="flex gap-1">
              {SEVERITIES.map((s) => (
                <Button key={s} size="sm" variant={severity === s ? "default" : "outline"} onClick={() => setSeverity(s)}>
                  {s}
                </Button>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-3 space-y-1">
          <Label>nuclei 模板 YAML</Label>
          <Textarea rows={10} className="font-mono text-xs" value={template} onChange={(e) => setTemplate(e.target.value)} />
        </div>
        <div className="mt-3">
          <Button
            size="sm"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              const payload = { title, component, cve, severity, template };
              const call = initial ? api.pocUpdate(initial.id, payload) : api.pocCreate(payload);
              call
                .then(() => {
                  toast.success(initial ? "已更新" : "已创建");
                  onDone();
                })
                .catch((e) => toast.error(`保存失败：${e.message}`))
                .finally(() => setBusy(false));
            }}
          >
            保存
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
