"use client";

import * as React from "react";

import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type {
  FindingDedupEvent,
  FindingRegression,
  FindingReview,
  ReviewVerdict,
} from "@/lib/types";

const VERDICTS: { value: ReviewVerdict; label: string; hint: string }[] = [
  { value: "confirmed", label: "确认", hint: "证据成立，状态改为已确认" },
  { value: "downgraded", label: "降级", hint: "证据不足以支撑当前等级，严重度降一档并确认" },
  { value: "rejected", label: "驳回", hint: "证据不成立，状态改为误报（留痕不删除）" },
];

function fmtTime(ts: string) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("zh-CN");
}

function verdictLabel(v: string) {
  return VERDICTS.find((x) => x.value === v)?.label ?? v;
}

// FindingReviewPanel 是 v0.6.4 质量闭环的 UI：复核（确认/降级/驳回）+ 复核记录 +
// 指纹去重记录 + 确定性回归 spec。复核是状态机的一部分，驳回/降级只留痕不删除。
export function FindingReviewPanel({
  findingId,
  readOnly,
  onReviewed,
}: {
  findingId: string;
  readOnly?: boolean;
  onReviewed?: () => void;
}) {
  const [verdict, setVerdict] = React.useState<ReviewVerdict>("confirmed");
  const [note, setNote] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [reviews, setReviews] = React.useState<FindingReview[]>([]);
  const [dedupEvents, setDedupEvents] = React.useState<FindingDedupEvent[]>([]);
  const [regression, setRegression] = React.useState<FindingRegression | null>(null);
  const [loaded, setLoaded] = React.useState(false);

  const load = React.useCallback(() => {
    Promise.all([
      api.findingReviews(findingId).catch(() => [] as FindingReview[]),
      api.findingDedupEvents(findingId).catch(() => [] as FindingDedupEvent[]),
      api.findingRegression(findingId).catch(() => null),
    ])
      .then(([r, d, g]) => {
        setReviews(r);
        setDedupEvents(d);
        setRegression(g);
      })
      .finally(() => setLoaded(true));
  }, [findingId]);

  React.useEffect(() => {
    load();
  }, [load]);

  const submit = React.useCallback(async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      const { review } = await api.reviewFinding(findingId, verdict, note.trim() || undefined);
      toast.success(
        `已复核：${verdictLabel(review.verdict)}（${statusMeta("severity", review.new_severity).label} · ${statusMeta("finding", review.new_status).label}）`,
      );
      setNote("");
      load();
      onReviewed?.();
    } catch (e) {
      toast.error("复核失败：" + (e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }, [findingId, load, note, onReviewed, submitting, verdict]);

  const selected = VERDICTS.find((x) => x.value === verdict);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">复核与质量闭环</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {!readOnly && (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Select value={verdict} onValueChange={(v) => setVerdict(v as ReviewVerdict)}>
                <SelectTrigger size="sm" className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {VERDICTS.map((v) => (
                    <SelectItem key={v.value} value={v.value}>
                      {v.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={() => void submit()} disabled={submitting}>
                {submitting ? "提交中…" : "提交复核"}
              </Button>
              <span className="text-xs text-muted-foreground">{selected?.hint}</span>
            </div>
            <Textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="复核备注（可选）：写清判断依据，方便以后追溯"
              rows={2}
            />
          </div>
        )}

        {loaded && reviews.length === 0 && dedupEvents.length === 0 && !regression && (
          <p className="text-sm text-muted-foreground">暂无复核记录、去重记录与回归 spec。</p>
        )}

        {reviews.length > 0 && (
          <div className="flex flex-col gap-2">
            <p className="text-xs font-medium text-muted-foreground">复核记录（{reviews.length}）</p>
            {reviews.map((r) => (
              <div key={r.id} className="flex flex-col gap-1 rounded-md border px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{verdictLabel(r.verdict)}</Badge>
                  <span className="text-xs text-muted-foreground">
                    {r.reviewer} · {fmtTime(r.created_at)}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  {statusMeta("severity", r.prev_severity).label} / {statusMeta("finding", r.prev_status).label}
                  {" → "}
                  {statusMeta("severity", r.new_severity).label} / {statusMeta("finding", r.new_status).label}
                </div>
                {r.note && <p className="text-sm whitespace-pre-wrap">{r.note}</p>}
              </div>
            ))}
          </div>
        )}

        {dedupEvents.length > 0 && (
          <div className="flex flex-col gap-2">
            <p className="text-xs font-medium text-muted-foreground">
              去重记录（{dedupEvents.length}）：指纹命中被拦的复报，可查不静默
            </p>
            {dedupEvents.map((e) => (
              <div key={e.id} className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-xs">
                <code className="max-w-full truncate rounded bg-muted px-1.5 py-0.5 font-mono" title={e.fingerprint}>
                  {e.fingerprint}
                </code>
                <span className="text-muted-foreground">
                  {e.vulnclass}
                  {e.name ? ` · ${e.name}` : ""} · {fmtTime(e.created_at)}
                </span>
              </div>
            ))}
          </div>
        )}

        {regression && (
          <div className="flex flex-col gap-1">
            <Separator />
            <p className="text-xs font-medium text-muted-foreground">确定性回归 spec（只记录，不自动回放）</p>
            <code className="rounded bg-muted px-2 py-1 font-mono text-xs break-all">
              {regression.method} {regression.url}
            </code>
            <p className="text-xs text-muted-foreground">
              断言：{regression.assertion}
              {regression.expected_status ? ` · 期望状态码 ${regression.expected_status}` : ""}
              {regression.last_verdict ? ` · 上次复核 ${regression.last_verdict}` : " · 尚未复核"}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// EvidenceBadge 行内展示：详情页顶栏与状态区共用。
export function EvidenceBadges({ finding }: { finding: { evidence_level?: string; report_excluded?: boolean } }) {
  return (
    <>
      {finding.evidence_level ? <StatusBadge domain="evidence" value={finding.evidence_level} /> : null}
      {finding.report_excluded ? (
        <Badge variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400">
          未达交付标准
        </Badge>
      ) : null}
    </>
  );
}
