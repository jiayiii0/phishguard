import { motion } from "framer-motion";
import { Eye, Gauge, ShieldAlert, Sparkles } from "lucide-react";

import { severityFromScore } from "../lib/format";
import { CyberVisual } from "./CyberVisual";
import { Scanner } from "./Scanner";
import { StatusTile } from "./StatusTile";

export function Hero({ onResult, result }) {
  const risk = severityFromScore(result?.risk_score || 0, result?.is_phishing);

  return (
    <section className="relative overflow-hidden px-5 py-12 md:py-16">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(56,189,248,.22),transparent_34%),linear-gradient(135deg,rgba(29,78,216,.18),transparent_40%)]" />
      <div className="cyber-background absolute inset-0 opacity-70" />
      <div className="relative mx-auto grid max-w-7xl items-center gap-8 lg:grid-cols-[.95fr_1.05fr] xl:gap-10">
        <div>
          <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/25 bg-cyan-300/10 px-3 py-2 text-sm font-bold text-cyan-100">
            <Sparkles size={16} /> Enterprise URL Intelligence
          </motion.div>
          <motion.h1 initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="mt-6 max-w-4xl text-5xl font-black leading-[1.02] text-white md:text-6xl xl:text-7xl">
            Detect Phishing Before It Strikes
          </motion.h1>
          <motion.p initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="mt-5 max-w-3xl text-lg font-medium leading-8 text-slate-300 md:text-xl">
            AI-powered real-time phishing detection using advanced XGBoost machine learning and URL intelligence.
          </motion.p>
          <div className="mt-8">
            <Scanner onResult={onResult} />
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            <StatusTile icon={<Gauge />} label="Risk Score" value={result ? result.risk_score : "--"} detail="0-100 engine" color={risk.color} />
            <StatusTile icon={<Eye />} label="Confidence" value={result ? `${result.confidence}%` : "--"} detail="model certainty" color="#67e8f9" />
            <StatusTile icon={<ShieldAlert />} label="Threat Level" value={result ? result.threat_level : "Awaiting scan"} detail="severity tier" color={risk.color} />
          </div>
        </div>
        <CyberVisual />
      </div>
    </section>
  );
}
