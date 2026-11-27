// 检测规则 —— artex-global detections/ 移植（v0.6.6）：Sigma 规则包（9 条）、
// ATT&CK 覆盖率自检、待复核队列、IoC 导出与防守制品下载。
// 诚实口径：规则检测的是 FORANG 自身的运行指纹（富化探针 UA、自更新 UA、
// 平台管控标记、破坏性命令、录制代理 CA），不是通用漏洞类别；命中只说明
// 某 finding 的已记录证据里出现了本工具自身发出的信号，缺席不等于安全。
"use client";

import React from "react";
import Link from "next/link";
import { ShieldAlert, DownloadIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { DetectionCoverage, DetectionRule, DetectionTriageItem } from "@/lib/types";

export default function DetectionsPage() {
  const [rules, setRules] = React.useState<DetectionRule[]>([]);
  const [coverage, setCoverage] = React.useState<DetectionCoverage | null>(null);
  const [queue, setQueue] = React.useState<DetectionTriageItem[]>([]);
  const [loaded, setLoaded] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const [r, c, q] = await Promise.all([
        api.detectionRules(),
        api.detectionCoverage(),
        api.detectionTriage(),
      ]);
      setRules(r);
      setCoverage(c);
      setQueue(q);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载检测规则失败");
    } finally {
      setLoaded(true);
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const toggle = React.useCallback(async (rule: DetectionRule) => {
    try {
      await api.setDetectionRule(rule.rule_id, !rule.enabled);
      toast.success(`${rule.slug} 已${rule.enabled ? "禁用" : "启用"}`);
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "切换失败");
    }
  }, [load]);

  const levelBadge = (level: string) =>
    level === "high" ? <Badge variant="destructive">high</Badge> : <Badge variant="secondary">medium</Badge>;

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <ShieldAlert className="size-5" /> 检测规则
        </h1>
        <div className="flex flex-wrap gap-2">
          <a href="/api/detections/ioc.csv">
            <Button variant="outline" size="sm">
              <DownloadIcon className="size-4" /> IoC 导出（CSV）
            </Button>
          </a>
          <a href="/api/detections/indicators.csv">
            <Button variant="outline" size="sm">指标清单</Button>
          </a>
          <a href="/api/detections/navigator_layer.json">
            <Button variant="outline" size="sm">ATT&amp;CK 层</Button>
          </a>
          <a href="/api/detections/suricata.rules">
            <Button variant="outline" size="sm">Suricata 规则</Button>
          </a>
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        规则包移植自 artex-global detections/（Sigma 9 条：原子 5、关联 4；ATT&amp;CK 8 技术；
        Suricata 3 条；IoC 7 行）。规则检测的是 FORANG 自身的运行指纹，命中只说明某 finding
        的已记录证据里出现了本工具自身发出的信号——不是漏洞本身更严重，缺席也不等于安全。
        关联规则需要真实事件时间线，只在覆盖率自检里按任务跑，不在登记时算。
      </p>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">规则清单（{rules.length} 条）</CardTitle>
          </CardHeader>
          <CardContent>
            {!loaded ? (
              <p className="text-sm text-muted-foreground">加载中…</p>
            ) : rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">规则包未加载。</p>
            ) : (
              <ul className="space-y-2">
                {rules.map((r) => (
                  <li key={r.rule_id} className="flex items-center justify-between gap-3 rounded-md border p-2.5">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm">{r.slug}</span>
                        {levelBadge(r.level)}
                        <Badge variant="outline">{r.kind}</Badge>
                      </div>
                      <p className="mt-1 truncate text-xs text-muted-foreground">{r.title}</p>
                    </div>
                    <Switch checked={r.enabled} onCheckedChange={() => toggle(r)} aria-label={r.slug} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">覆盖率自检</CardTitle>
            </CardHeader>
            <CardContent>
              {!coverage ? (
                <p className="text-sm text-muted-foreground">加载中…</p>
              ) : (
                <div className="space-y-2 text-sm">
                  <p>
                    ATT&amp;CK 技术：{coverage.techniques.filter((t) => t.enabled_rules > 0).length} /{" "}
                    {coverage.techniques.length} 有启用规则
                    {coverage.uncovered_techniques.length > 0
                      ? `（无覆盖：${coverage.uncovered_techniques.join(", ")}）`
                      : ""}
                  </p>
                  <p>
                    漏洞类别：{coverage.classes.filter((c) => c.covered).length} / {coverage.classes.length}{" "}
                    有规则覆盖
                  </p>
                  {coverage.uncovered_classes.length > 0 ? (
                    <p className="text-muted-foreground">
                      无覆盖类别：{coverage.uncovered_classes.join("、")}——这些类别的证据里没有
                      本包规则的 token，是本包的能力边界，不是缺陷。
                    </p>
                  ) : (
                    <p className="text-muted-foreground">全部已有类别均有规则覆盖。</p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">待复核队列（按严重度 / 证据等级 / 命中数排序）</CardTitle>
            </CardHeader>
            <CardContent>
              {queue.length === 0 ? (
                <p className="text-sm text-muted-foreground">没有待复核的 finding。</p>
              ) : (
                <ul className="space-y-2">
                  {queue.slice(0, 10).map((q) => (
                    <li key={q.finding_id} className="flex items-center justify-between gap-3 rounded-md border p-2.5">
                      <Link
                        href={`/function/findings/detail?id=${q.finding_id}`}
                        className="min-w-0 text-sm hover:underline"
                      >
                        <span className="font-medium">{q.name || q.vulnclass}</span>
                        <span className="ml-2 text-xs text-muted-foreground">
                          {q.severity} · {q.evidence_level || "未分级"} · 命中 {q.hit_count} 条
                        </span>
                      </Link>
                      <div className="flex shrink-0 gap-1">
                        {q.rule_slugs.map((s) => (
                          <Badge key={s} variant="outline">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
