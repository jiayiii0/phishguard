import { motion } from "framer-motion";
import { AlertTriangle, BrainCircuit, FileJson, Globe2, Radar } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";

import { cleanFeatureName, exportJson, resultNarrative, severityFromScore } from "../lib/format";
import { StatusTile } from "./StatusTile";

export function ResultPanel({ result }) {
  if (!result) {
    return (
      <section id="result" className="mx-auto max-w-7xl px-5">
        <div className="glass-panel rounded-lg p-8 text-center">
          <Radar className="mx-auto text-cyan-200" size={42} />
          <h2 className="mt-4 text-2xl font-black text-white">No active scan yet</h2>
          <p className="mt-2 text-slate-400">Submit a URL in the hero scanner to generate a real-time threat report.</p>
        </div>
      </section>
    );
  }

  const severity = severityFromScore(result.risk_score, result.is_phishing);
  const riskData = [
    { name: "Risk", value: result.risk_score },
    { name: "Remaining", value: Math.max(100 - result.risk_score, 0) },
  ];
  const evasionTechniques = result.evasion_techniques || [];
  const redirectChain = result.redirect_chain || [];

  return (
    <section id="result" className="mx-auto mt-4 grid max-w-7xl gap-5 px-5 lg:grid-cols-[1.15fr_.85fr]">
      <motion.div className="glass-panel rounded-lg p-6" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex flex-col gap-5 md:flex-row md:items-start md:justify-between">
          <div>
            <span className="inline-flex rounded-lg border px-3 py-2 text-sm font-black" style={{ color: severity.color, background: severity.bg, borderColor: severity.border }}>
              {result.threat_level}
            </span>
            <h2 className="mt-5 text-3xl font-black text-white">{result.is_phishing ? "Phishing pattern detected" : "No critical phishing pattern detected"}</h2>
            <p className="mt-2 break-all text-sm font-semibold text-slate-400">{result.url}</p>
          </div>
          <button onClick={() => exportJson(`phishguard-scan-${Date.now()}.json`, result)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-300/25 bg-cyan-300/10 px-4 py-3 text-sm font-black text-cyan-100 transition hover:bg-cyan-300/20">
            <FileJson size={18} /> Export Report
          </button>
        </div>
        <div className="mt-6 grid gap-3 md:grid-cols-3">
          <StatusTile icon={<BrainCircuit />} label="Prediction" value={result.result} detail="XGBoost classifier" color={severity.color} />
          <StatusTile icon={<Globe2 />} label="Hostname" value={result.hostname || "N/A"} detail="parsed target" />
          <StatusTile icon={<AlertTriangle />} label="Indicators" value={result.indicators.length} detail="risk signals" color="#facc15" />
        </div>
        <div className="mt-6">
          <h3 className="text-lg font-black text-white">Detection Summary</h3>
          <div className="mt-3 rounded-lg border border-cyan-300/20 bg-cyan-300/10 p-4 text-sm font-semibold leading-6 text-cyan-50">
            {resultNarrative(result)}
          </div>
          <div className="mt-3 grid gap-2">
            {(result.indicators.length ? result.indicators : ["No high-risk URL indicator was detected."]).map((item) => (
              <div key={item} className="rounded-lg border border-white/10 bg-white/[.04] px-4 py-3 text-sm font-semibold text-slate-300">
                {item}
              </div>
            ))}
          </div>
        </div>
        <div className="mt-6 rounded-lg border border-white/10 bg-black/20 p-4">
          <h3 className="text-lg font-black text-white">URL Intelligence</h3>
          <div className="mt-4 grid gap-3 text-sm">
            <div>
              <div className="text-xs font-black uppercase text-slate-500">Normalized URL</div>
              <div className="mt-1 break-all font-semibold text-slate-300">{result.normalized_url || result.url}</div>
            </div>
            <div>
              <div className="text-xs font-black uppercase text-slate-500">Expanded URL</div>
              <div className="mt-1 break-all font-semibold text-slate-300">{result.expanded_url || result.normalized_url || result.url}</div>
            </div>
            <div>
              <div className="text-xs font-black uppercase text-slate-500">Final Destination</div>
              <div className="mt-1 break-all font-semibold text-slate-300">{result.final_destination || result.hostname || "N/A"}</div>
            </div>
          </div>
            <div>
              <div className="text-xs font-black uppercase text-slate-500">Threat Feed Evidence</div>
              <div className="mt-1 break-all font-semibold text-slate-300">{result.threat_feed_status || "disabled"}{result.threat_feed_source ? ` - ${result.threat_feed_source}` : ""}</div>
            </div>
          <div className="mt-4">
            <div className="text-xs font-black uppercase text-slate-500">Detected Evasion Techniques</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {(evasionTechniques.length ? evasionTechniques : ["none_detected"]).map((item) => (
                <span key={item} className="rounded-lg border border-cyan-300/20 bg-cyan-300/10 px-3 py-2 text-xs font-black text-cyan-100">
                  {cleanFeatureName(item)}
                </span>
              ))}
            </div>
          </div>
          {redirectChain.length > 1 && (
            <div className="mt-4">
              <div className="text-xs font-black uppercase text-slate-500">Redirect Chain</div>
              <div className="mt-2 grid gap-2">
                {redirectChain.map((url, index) => (
                  <div key={`${url}-${index}`} className="break-all rounded-lg border border-white/10 bg-white/[.04] px-3 py-2 text-xs font-semibold text-slate-300">
                    {index + 1}. {url}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </motion.div>
      <motion.div className="glass-panel rounded-lg p-6" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xl font-black text-white">AI Risk Meter</h3>
            <p className="mt-1 text-sm text-slate-400">Confidence {result.confidence}%</p>
          </div>
          <div className="text-right">
            <div className="text-5xl font-black" style={{ color: severity.color }}>{result.risk_score}</div>
            <div className="text-xs font-bold uppercase text-slate-500">risk score</div>
          </div>
        </div>
        <div className="mt-4 h-52">
          <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
            <PieChart>
              <Pie data={riskData} dataKey="value" innerRadius={58} outerRadius={86} startAngle={90} endAngle={-270}>
                <Cell fill={severity.color} />
                <Cell fill="rgba(148,163,184,.16)" />
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <h4 className="mt-2 font-black text-white">Top Explanation Factors</h4>
        <div className="mt-3 space-y-2">
          {result.shap_factors.slice(0, 5).map((factor) => (
            <div key={factor.feature} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-black/20 px-3 py-2">
              <div className="truncate text-sm font-bold text-slate-200">{cleanFeatureName(factor.feature)}</div>
              <div className={factor.direction === "raises risk" ? "text-sm font-black text-rose-300" : "text-sm font-black text-emerald-300"}>
                {factor.direction}
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </section>
  );
}
