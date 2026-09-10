import { useMemo, useState } from "react";
import { Activity, BarChart3, CheckCircle2, ClipboardList, Eraser, ShieldAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { severityFromScore } from "../lib/format";
import { SectionHeading } from "./SectionHeading";
import { StatusTile } from "./StatusTile";

export function Dashboard({ stats, onClear }) {
  const [filter, setFilter] = useState("All");
  const riskData = useMemo(() => [
    { name: "Low", value: stats?.risk_buckets?.low || 0, fill: "#34d399" },
    { name: "Medium", value: stats?.risk_buckets?.medium || 0, fill: "#facc15" },
    { name: "High", value: stats?.risk_buckets?.high || 0, fill: "#fb7185" },
  ], [stats]);

  const recentScans = stats?.recent_scans || [];
  const filtered = recentScans.filter((scan) => {
    const severity = severityFromScore(scan.risk_score, scan.is_phishing).label;
    if (filter === "All") return true;
    if (filter === "Phishing") return scan.is_phishing;
    if (filter === "Safe") return !scan.is_phishing;
    return severity === filter;
  });

  return (
    <section id="dashboard" className="mx-auto mt-14 max-w-7xl px-5 pb-16">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <SectionHeading eyebrow="Command Center" title="Threat dashboard built for security review" text="Track scan outcomes, risk distribution, confidence signals, and recent detections in an enterprise-style workspace." />
        <div className="flex flex-wrap gap-2">
          <button onClick={onClear} className="inline-flex items-center gap-2 rounded-lg border border-rose-300/25 bg-rose-500/10 px-4 py-3 text-sm font-black text-rose-100 transition hover:bg-rose-500/20">
            <Eraser size={17} /> Clear History
          </button>
          <a href="/docs" className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/25 bg-cyan-300/10 px-4 py-3 text-sm font-black text-cyan-100 transition hover:bg-cyan-300/20">
            <ClipboardList size={17} /> API Docs
          </a>
        </div>
      </div>
      <div className="mt-7 grid gap-3 md:grid-cols-4">
        <StatusTile icon={<Activity />} label="Total Scans" value={stats?.total_scans || 0} detail="stored records" />
        <StatusTile icon={<ShieldAlert />} label="Phishing" value={stats?.phishing_detected || 0} detail="detected threats" color="#fb7185" />
        <StatusTile icon={<CheckCircle2 />} label="Safe" value={stats?.safe_detected || 0} detail="safe results" color="#34d399" />
        <StatusTile icon={<BarChart3 />} label="Avg Risk" value={stats?.average_risk_score || 0} detail="0-100 score" color="#facc15" />
      </div>
      <div className="mt-5 grid gap-5 lg:grid-cols-[.8fr_1.2fr]">
        <div className="glass-panel rounded-lg p-5">
          <h3 className="text-lg font-black text-white">Risk Distribution</h3>
          <div className="mt-4 h-72">
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <BarChart data={riskData}>
                <CartesianGrid stroke="rgba(148,163,184,.12)" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fill: "#94a3b8", fontSize: 12 }} />
                <Tooltip contentStyle={{ background: "#08111f", border: "1px solid rgba(255,255,255,.14)", borderRadius: 8, color: "#e2e8f0" }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {riskData.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="glass-panel rounded-lg p-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <h3 className="text-lg font-black text-white">Detection History</h3>
            <div className="flex flex-wrap gap-2">
              {["All", "Safe", "Low Risk", "Suspicious", "High Risk", "Phishing"].map((item) => (
                <button key={item} onClick={() => setFilter(item)} className={`rounded-lg px-3 py-2 text-xs font-black transition ${filter === item ? "bg-cyan-300 text-slate-950" : "border border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"}`}>
                  {item}
                </button>
              ))}
            </div>
          </div>
          <div className="mt-4 space-y-3">
            {filtered.length === 0 && <div className="rounded-lg border border-white/10 bg-white/[.04] p-5 text-sm font-semibold text-slate-400">No scans match this filter.</div>}
            {filtered.map((scan) => {
              const severity = severityFromScore(scan.risk_score, scan.is_phishing);
              return (
                <div key={scan.id} className="rounded-lg border border-white/10 bg-black/20 p-4 transition hover:border-cyan-300/25">
                  <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <div className="min-w-0">
                      <div className="break-all text-sm font-bold text-white">{scan.url}</div>
                      <div className="mt-1 text-xs font-semibold text-slate-500">{new Date(scan.created_at).toLocaleString()}</div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="rounded-lg border px-3 py-2 text-xs font-black" style={{ color: severity.color, background: severity.bg, borderColor: severity.border }}>{severity.label}</span>
                      <span className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs font-black text-white">Risk {scan.risk_score}</span>
                      <span className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs font-black text-cyan-100">{scan.confidence}%</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
