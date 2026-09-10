import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { cleanFeatureName, formatNumber } from "../lib/format";
import { EvidenceStat } from "./EvidenceStat";
import { SectionHeading } from "./SectionHeading";

export function ModelEvidence({ metrics }) {
  const matrix = metrics?.confusion_matrix || [[0, 0], [0, 0]];
  const featureImportance = metrics?.feature_importance || [];
  const featureData = featureImportance.slice(0, 8).map((item) => ({
    feature: cleanFeatureName(item.feature),
    importance: Number((item.importance * 100).toFixed(2)),
  }));
  const matrixItems = [
    { label: "True Safe", value: matrix?.[0]?.[0] || 0, color: "text-emerald-300" },
    { label: "False Alert", value: matrix?.[0]?.[1] || 0, color: "text-amber-300" },
    { label: "Missed Phish", value: matrix?.[1]?.[0] || 0, color: "text-rose-300" },
    { label: "True Phish", value: matrix?.[1]?.[1] || 0, color: "text-cyan-200" },
  ];

  return (
    <section id="evidence" className="mx-auto mt-14 max-w-7xl px-5">
      <SectionHeading eyebrow="Model Evidence" title="XGBoost training evidence built into the product" text="The platform exposes training sources, evaluation metrics, confusion matrix, and top feature importance for transparent model review." />
      <div className="mt-7 grid gap-5 lg:grid-cols-[.9fr_1.1fr]">
        <div className="glass-panel rounded-lg p-5">
          <h3 className="text-xl font-black text-white">Training Summary</h3>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <EvidenceStat label="Dataset Size" value={formatNumber(metrics?.dataset_size)} />
            <EvidenceStat label="Feature Count" value={metrics?.feature_count || 0} />
            <EvidenceStat label="Recall" value={metrics?.recall ?? "--"} />
            <EvidenceStat label="F1 Score" value={metrics?.f1_score ?? "--"} />
            <EvidenceStat label="CV F1 Mean" value={metrics?.cv_f1_mean ?? "--"} />
            <EvidenceStat label="Threshold" value={metrics?.selected_threshold ?? "--"} />
          </div>
          <div className="mt-5 rounded-lg border border-white/10 bg-white/[.04] p-4">
            <div className="font-black text-white">Training Sources</div>
            <div className="mt-3 space-y-2">
              {(metrics?.training_sources || []).map((source) => (
                <div key={source} className="text-sm font-semibold text-slate-300">{source}</div>
              ))}
            </div>
          </div>
        </div>
        <div className="grid gap-5 md:grid-cols-2">
          <div className="glass-panel rounded-lg p-5">
            <h3 className="text-lg font-black text-white">Confusion Matrix</h3>
            <div className="mt-4 grid grid-cols-2 gap-3">
              {matrixItems.map((item) => (
                <div key={item.label} className="rounded-lg border border-white/10 bg-black/20 p-4">
                  <div className={`text-3xl font-black ${item.color}`}>{formatNumber(item.value)}</div>
                  <div className="mt-1 text-xs font-bold uppercase text-slate-500">{item.label}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="glass-panel rounded-lg p-5">
            <h3 className="text-lg font-black text-white">Feature Importance</h3>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
                <BarChart data={featureData} layout="vertical" margin={{ left: 8, right: 10, top: 6, bottom: 6 }}>
                  <CartesianGrid stroke="rgba(148,163,184,.12)" horizontal={false} />
                  <XAxis type="number" hide />
                  <YAxis dataKey="feature" type="category" width={112} tick={{ fill: "#94a3b8", fontSize: 11 }} />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,.05)" }} contentStyle={{ background: "#08111f", border: "1px solid rgba(255,255,255,.14)", borderRadius: 8, color: "#e2e8f0" }} />
                  <Bar dataKey="importance" fill="#22d3ee" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
