"use client";

// 内网作战（v0.6.3 artex-ymh 移植）：凭据库 / 隧道台账 / 待授权网段 / 拓扑与蜜罐。
// 凭据 secret 只进不出：列表只给元数据；新建走加密入库；删除/验证走接口。
// 隧道只做计划生成 + 入账（state=deploying）；远端投递需立足点会话（FORANG
// 暂无），deploy 为后续项——页面不提供「一键部署」假按钮。

import * as React from "react";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { IntranetOverview, Task } from "@/lib/types";

const CRED_TYPES = ["password", "hash_nt", "hash_lm", "hash_sha1", "ticket", "ssh_key", "token"];

export default function IntranetPage() {
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [taskId, setTaskId] = React.useState("");
  const [ov, setOv] = React.useState<IntranetOverview | null>(null);
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async (id: string) => {
    if (!id) return;
    setLoading(true);
    try {
      setOv(await api.intranetOverview(id));
    } catch (e) {
      toast.error(`加载失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    api.tasks().then(({ tasks: ts }) => {
      setTasks(ts);
      if (ts.length > 0) {
        const first = String(ts[0].id);
        setTaskId(first);
        void load(first);
      }
    }).catch(() => undefined);
  }, [load]);

  const onTaskChange = (id: string) => {
    setTaskId(id);
    void load(id);
  };

  const creds = ov?.credentials ?? [];
  const tunnels = ov?.tunnels ?? [];
  const pending = ov?.pending_scope ?? [];
  const honeypots = ov?.honeypot_assets ?? [];
  const topo = ov?.topology;

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div>
          <h1 className="font-semibold text-xl">内网作战</h1>
          <p className="text-muted-foreground text-sm">凭据库 · 隧道台账 · 待授权网段 · 拓扑与蜜罐（v0.6.3 ymh 移植）</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Label htmlFor="intranet-task">任务</Label>
          <Select value={taskId} onValueChange={onTaskChange}>
            <SelectTrigger id="intranet-task" className="w-64">
              <SelectValue placeholder="选择任务" />
            </SelectTrigger>
            <SelectContent>
              {tasks.map((t) => (
                <SelectItem key={t.id} value={String(t.id)}>
                  #{t.id} · {t.description || "未命名任务"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" disabled={!taskId || loading} onClick={() => void load(taskId)}>
            刷新
          </Button>
        </div>
      </div>

      {!taskId ? (
        <p className="text-sm text-muted-foreground">暂无任务。</p>
      ) : (
        <Tabs defaultValue="credentials">
          <TabsList>
            <TabsTrigger value="credentials">凭据库（{creds.length}）</TabsTrigger>
            <TabsTrigger value="tunnels">隧道（{tunnels.length}）</TabsTrigger>
            <TabsTrigger value="pending">待授权网段（{pending.filter((p) => p.status === "pending").length}）</TabsTrigger>
            <TabsTrigger value="topology">拓扑与蜜罐（{honeypots.length}）</TabsTrigger>
          </TabsList>

          <TabsContent value="credentials" className="mt-4">
            <CredentialPanel taskId={taskId} creds={creds} onReload={() => void load(taskId)} />
          </TabsContent>
          <TabsContent value="tunnels" className="mt-4">
            <TunnelPanel taskId={taskId} tunnels={tunnels} onReload={() => void load(taskId)} />
          </TabsContent>
          <TabsContent value="pending" className="mt-4">
            <PendingPanel taskId={taskId} pending={pending} onReload={() => void load(taskId)} />
          </TabsContent>
          <TabsContent value="topology" className="mt-4">
            <TopologyPanel ov={ov} />
          </TabsContent>
        </Tabs>
      )}
      {topo == null && taskId && !loading ? null : null}
    </div>
  );
}

function CredentialPanel({ taskId, creds, onReload }: {
  taskId: string;
  creds: NonNullable<IntranetOverview["credentials"]>;
  onReload: () => void;
}) {
  const [username, setUsername] = React.useState("");
  const [credType, setCredType] = React.useState("password");
  const [secret, setSecret] = React.useState("");
  const [domain, setDomain] = React.useState("");
  const [source, setSource] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const submit = async () => {
    if (!username.trim() || !secret.trim() || !source.trim()) {
      toast.error("用户名、secret、来源都要填");
      return;
    }
    setBusy(true);
    try {
      await api.createCredential(taskId, {
        username: username.trim(), cred_type: credType, secret,
        domain: domain.trim(), source: source.trim(),
      });
      toast.success("凭据已加密入库");
      setUsername(""); setSecret(""); setDomain(""); setSource("");
      onReload();
    } catch (e) {
      toast.error(`入库失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader><CardTitle className="text-base">登记凭据（AES-GCM 加密落库，secret 只进不出）</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1"><Label>用户名</Label><Input value={username} onChange={(e) => setUsername(e.target.value)} className="w-40" /></div>
          <div className="grid gap-1"><Label>类型</Label>
            <Select value={credType} onValueChange={setCredType}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>{CRED_TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="grid gap-1"><Label>Secret</Label><Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className="w-52" autoComplete="off" /></div>
          <div className="grid gap-1"><Label>域（可选）</Label><Input value={domain} onChange={(e) => setDomain(e.target.value)} className="w-32" placeholder="CORP" /></div>
          <div className="grid gap-1"><Label>来源</Label><Input value={source} onChange={(e) => setSource(e.target.value)} className="w-64" placeholder="如 sqli dump users 表" /></div>
          <Button onClick={() => void submit()} disabled={busy}>入库</Button>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <Table>
            <TableHeader><TableRow>
              <TableHead>ID</TableHead><TableHead>用户名</TableHead><TableHead>类型</TableHead>
              <TableHead>域</TableHead><TableHead>来源</TableHead><TableHead>已验证</TableHead><TableHead>操作</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {creds.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">暂无凭据。</TableCell></TableRow>
              ) : creds.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs">{c.id}</TableCell>
                  <TableCell className="font-mono text-xs">{c.username}</TableCell>
                  <TableCell><Badge variant="secondary" className="font-mono text-[10px]">{c.cred_type}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{c.domain || "—"}</TableCell>
                  <TableCell className="max-w-[16rem] truncate text-xs" title={c.source}>{c.source}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => void api.verifyCredential(taskId, c.id, !c.verified).then(onReload).catch((e: unknown) => toast.error(String(e)))}>
                      {c.verified ? "✓ 已验证" : "未验证"}
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" className="text-destructive" onClick={() => void api.deleteCredential(taskId, c.id).then(onReload).catch((e: unknown) => toast.error(String(e)))}>删除</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function TunnelPanel({ taskId, tunnels, onReload }: {
  taskId: string;
  tunnels: NonNullable<IntranetOverview["tunnels"]>;
  onReload: () => void;
}) {
  const [kind, setKind] = React.useState("socks");
  const [tcpOut, setTcpOut] = React.useState(true);
  const [webshellUrl, setWebshellUrl] = React.useState("");
  const [targetHost, setTargetHost] = React.useState("");
  const [targetPort, setTargetPort] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [lastPlan, setLastPlan] = React.useState<string>("");

  const submit = async () => {
    setBusy(true);
    try {
      const r = await api.createTunnelPlan(taskId, {
        kind, tcp_out: tcpOut, webshell_url: webshellUrl.trim() || undefined,
        target_host: targetHost.trim() || undefined,
        target_port: targetPort ? Number(targetPort) : undefined,
      });
      setLastPlan(`#${r.tunnel_id} ${r.adapter} · ${r.listen} · ${r.socks_entry ?? r.local_entry ?? ""}（${r.selection_reason}）`);
      toast.success("隧道计划已生成并入账（deploying）");
      onReload();
    } catch (e) {
      toast.error(`计划生成失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader><CardTitle className="text-base">生成隧道计划（选型 + 端口分配 + 入账；远端投递为后续项）</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1"><Label>类型</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="socks">socks</SelectItem><SelectItem value="portfwd">portfwd</SelectItem></SelectContent>
            </Select>
          </div>
          <div className="grid gap-1"><Label>目标能 TCP 出网</Label>
            <Select value={tcpOut ? "yes" : "no"} onValueChange={(v) => setTcpOut(v === "yes")}>
              <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="yes">是</SelectItem><SelectItem value="no">否</SelectItem></SelectContent>
            </Select>
          </div>
          <div className="grid gap-1"><Label>Webshell URL（无出网时）</Label><Input value={webshellUrl} onChange={(e) => setWebshellUrl(e.target.value)} className="w-64" placeholder="http://10.0.0.5/shell.php" /></div>
          {kind === "portfwd" && (
            <>
              <div className="grid gap-1"><Label>内网目标 host</Label><Input value={targetHost} onChange={(e) => setTargetHost(e.target.value)} className="w-40" /></div>
              <div className="grid gap-1"><Label>内网目标 port</Label><Input value={targetPort} onChange={(e) => setTargetPort(e.target.value)} className="w-24" inputMode="numeric" /></div>
            </>
          )}
          <Button onClick={() => void submit()} disabled={busy}>生成计划</Button>
        </CardContent>
        {lastPlan && <CardContent className="pt-0 text-xs text-muted-foreground">{lastPlan}</CardContent>}
      </Card>
      <Card>
        <CardContent className="pt-4">
          <Table>
            <TableHeader><TableRow>
              <TableHead>ID</TableHead><TableHead>类型</TableHead><TableHead>适配器</TableHead>
              <TableHead>监听</TableHead><TableHead>目标</TableHead><TableHead>状态</TableHead><TableHead>操作</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {tunnels.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">暂无隧道。</TableCell></TableRow>
              ) : tunnels.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-mono text-xs">{t.id}</TableCell>
                  <TableCell>{t.kind}</TableCell>
                  <TableCell><Badge variant="secondary" className="font-mono text-[10px]">{t.adapter}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{t.listen_host}:{t.listen_port}</TableCell>
                  <TableCell className="font-mono text-xs">{t.target_host ? `${t.target_host}:${t.target_port}` : "—"}</TableCell>
                  <TableCell>
                    <Badge variant={t.state === "alive" ? "default" : t.state === "error" ? "destructive" : "outline"} className="font-mono text-[10px]">{t.state}</Badge>
                    {t.error && <div className="max-w-[12rem] truncate text-[11px] text-destructive" title={t.error}>{t.error}</div>}
                  </TableCell>
                  <TableCell className="flex gap-1">
                    <Button variant="ghost" size="sm" disabled={t.state === "alive"} onClick={() => void api.updateTunnelState(taskId, t.id, "alive").then(onReload).catch((e: unknown) => toast.error(String(e)))}>标 alive</Button>
                    <Button variant="ghost" size="sm" disabled={t.state === "stopped"} onClick={() => void api.updateTunnelState(taskId, t.id, "stopped").then(onReload).catch((e: unknown) => toast.error(String(e)))}>停用</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="mt-3 text-xs text-muted-foreground">注意：alive 只能由决定性验证（经隧道真实拨测）后标记；本页的「标 alive」是人工确认入口，不要对未验证的隧道点它。</p>
        </CardContent>
      </Card>
    </div>
  );
}

function PendingPanel({ taskId, pending, onReload }: {
  taskId: string;
  pending: NonNullable<IntranetOverview["pending_scope"]>;
  onReload: () => void;
}) {
  const [value, setValue] = React.useState("");
  const decide = async (sid: number, approved: boolean) => {
    try {
      await api.decidePendingScope(taskId, sid, approved);
      toast.success(approved ? "已批准并扩进 task_scope" : "已拒绝");
      onReload();
    } catch (e) {
      toast.error(`操作失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader><CardTitle className="text-base">登记待授权网段（批准后才扩范围）</CardTitle></CardHeader>
        <CardContent className="flex items-end gap-3">
          <div className="grid gap-1"><Label>网段（CIDR）</Label><Input value={value} onChange={(e) => setValue(e.target.value)} className="w-56" placeholder="10.0.3.0/24" /></div>
          <Button onClick={() => void api.createPendingScope(taskId, value.trim()).then(() => { setValue(""); onReload(); }).catch((e: unknown) => toast.error(String(e)))}>登记</Button>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <Table>
            <TableHeader><TableRow>
              <TableHead>ID</TableHead><TableHead>网段</TableHead><TableHead>状态</TableHead>
              <TableHead>命中</TableHead><TableHead>首次发现</TableHead><TableHead>操作</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {pending.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">暂无待授权网段。</TableCell></TableRow>
              ) : pending.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-mono text-xs">{p.id}</TableCell>
                  <TableCell className="font-mono text-xs">{p.value}</TableCell>
                  <TableCell><Badge variant={p.status === "approved" ? "default" : p.status === "dismissed" ? "secondary" : "outline"}>{p.status}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{p.hits}</TableCell>
                  <TableCell className="text-xs">{p.first_seen}</TableCell>
                  <TableCell className="flex gap-1">
                    {p.status === "pending" && (
                      <>
                        <Button variant="ghost" size="sm" onClick={() => void decide(p.id, true)}>批准扩范围</Button>
                        <Button variant="ghost" size="sm" onClick={() => void decide(p.id, false)}>拒绝</Button>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function TopologyPanel({ ov }: { ov: IntranetOverview | null }) {
  const honeypots = ov?.honeypot_assets ?? [];
  const nodes = ov?.topology?.nodes ?? [];
  const edges = ov?.topology?.edges ?? [];
  const hosts = nodes.filter((n) => n.kind === "host");
  const services = nodes.filter((n) => n.kind === "service");
  const bySegment = new Map<string, typeof hosts>();
  for (const h of hosts) {
    const seg = h.segment || "（未知网段）";
    const arr = bySegment.get(seg) ?? [];
    arr.push(h);
    bySegment.set(seg, arr);
  }
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader><CardTitle className="text-base">疑似蜜罐资产（L1 静态签名，单信号只降级交互）</CardTitle></CardHeader>
        <CardContent>
          {honeypots.length === 0 ? (
            <p className="text-sm text-muted-foreground">本任务暂无签名命中的疑似蜜罐。全阴性 ≠ 非蜜罐，仍不投放高价值 exploit、控制噪声。</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>ID</TableHead><TableHead>资产</TableHead><TableHead>评分</TableHead><TableHead>命中签名</TableHead></TableRow></TableHeader>
              <TableBody>
                {honeypots.map((h) => (
                  <TableRow key={h.id}>
                    <TableCell className="font-mono text-xs">{h.id}</TableCell>
                    <TableCell className="max-w-[16rem] truncate font-mono text-xs" title={h.label}>{h.label}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={h.score >= 0.9 ? "border-red-300 bg-red-50 text-red-700" : "border-amber-300 bg-amber-50 text-amber-700"}>
                        {h.score.toFixed(2)}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[24rem] truncate text-xs" title={h.evidence}>{h.evidence}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-base">内网拓扑（按任务过滤：主机 × 服务）</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
          {nodes.length === 0 ? (
            <p className="text-sm text-muted-foreground">本任务暂无可成图资产。</p>
          ) : (
            <>
              {[...bySegment.entries()].map(([seg, hs]) => (
                <div key={seg}>
                  <div className="mb-1 text-xs font-semibold">网段 {seg}（{hs.length} 台主机）</div>
                  <div className="flex flex-wrap gap-2">
                    {hs.map((h) => (
                      <Badge key={h.id} variant="outline" className={h.honeypot ? "border-red-300 text-red-700" : ""} title={h.honeypot ? "疑似蜜罐" : undefined}>
                        {h.ip} #{h.id}{h.honeypot ? " 蜜罐？" : ""}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
              <div>
                <div className="mb-1 text-xs font-semibold">服务（{services.length}）</div>
                <div className="flex flex-wrap gap-2">
                  {services.map((s) => (
                    <Badge key={s.id} variant="secondary" className="font-mono text-[10px]" title={s.honeypot ? "疑似蜜罐" : undefined}>
                      {s.label ?? s.ip}:{s.port ?? "?"} #{s.id}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="text-xs text-muted-foreground">边 {edges.length} 条（主机→服务 runs，同网段 same_segment）。完整关系图后续接可视化组件。</div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
