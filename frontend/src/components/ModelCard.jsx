import { AlertTriangle, BrainCircuit, Gauge } from "lucide-react";

import { formatNumber } from "../lib/format";
import { EvidenceStat } from "./EvidenceStat";
import { SectionHeading } from "./SectionHeading";

export function ModelCard({ metrics }) {
  return (
    <section className="mx-auto mt-14 max-w-7xl px-5">
      <SectionHeading
        eyebrow="Model Card"
        title="Transparent machine learning boundaries"
        text="A compact model card helps users and evaluators understand what the detector is designed to do, what evidence supports it, and where human caution is still required."
      />
      <div className="mt-7 grid gap-4 lg:grid-cols-3">
        <div className="glass-panel rounded-lg p-5">
          <div className="mb-4 grid h-11 w-11 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 text-cyan-100">
            <BrainCircuit size={22} />
          </div>
          <h3 className="text-lg font-black text-white">Intended Use</h3>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Classify public website URLs for phishing risk before users open links or submit sensitive information.
          </p>
          <div className="mt-4 rounded-lg border border-white/10 bg-black/20 p-3 text-sm font-bold text-slate-300">
            Primary engine: {metrics?.algorithm || "XGBoost"}
          </div>
        </div>
        <div className="glass-panel rounded-lg p-5">
          <div className="mb-4 grid h-11 w-11 place-items-center rounded-lg border border-emerald-300/20 bg-emerald-300/10 text-emerald-100">
            <Gauge size={22} />
          </div>
          <h3 className="text-lg font-black text-white">Evaluation Snapshot</h3>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <EvidenceStat label="URLs" value={formatNumber(metrics?.dataset_size)} />
            <EvidenceStat label="Features" value={metrics?.feature_count || 0} />
            <EvidenceStat label="Recall" value={metrics?.recall ?? "--"} />
            <EvidenceStat label="F1 Score" value={metrics?.f1_score ?? "--"} />
          </div>
        </div>
        <div className="glass-panel rounded-lg p-5">
          <div className="mb-4 grid h-11 w-11 place-items-center rounded-lg border border-amber-300/20 bg-amber-300/10 text-amber-100">
            <AlertTriangle size={22} />
          </div>
          <h3 className="text-lg font-black text-white">Known Limits</h3>
          <ul className="mt-3 space-y-3 text-sm leading-6 text-slate-400">
            <li>New phishing campaigns may appear before public datasets include them.</li>
            <li>URL-only scanning does not inspect full webpage content by default.</li>
            <li>High-risk decisions should be verified before blocking business-critical links.</li>
          </ul>
        </div>
      </div>
    </section>
  );
}
