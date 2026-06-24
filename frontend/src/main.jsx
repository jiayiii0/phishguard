import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { motion } from "framer-motion";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  BrainCircuit,
  CheckCircle2,
  ClipboardList,
  Download,
  Eraser,
  Eye,
  FileJson,
  Fingerprint,
  Gauge,
  Globe2,
  History,
  Layers3,
  Lock,
  Network,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TimerReset,
  Zap,
} from "lucide-react";
import "./styles.css";

const API = "/api/v1";

const featureCards = [
  { icon: <Zap />, title: "Real-Time URL Analysis", text: "Instant URL inspection without unsafe webpage crawling." },
  { icon: <BrainCircuit />, title: "XGBoost Threat Detection", text: "Primary ML classifier trained on large phishing and legitimate URL datasets." },
  { icon: <Layers3 />, title: "URL Structure Analysis", text: "Length, symbols, subdomains, entropy, encoding, and protocol checks." },
  { icon: <Globe2 />, title: "Domain Intelligence", text: "Hostname, TLD, brand impersonation, and typosquatting signals." },
  { icon: <Network />, title: "Redirect Pattern Detection", text: "Flags encoded characters, redirect-style paths, ports, and suspicious URL structure." },
  { icon: <Fingerprint />, title: "Suspicious Keyword Detection", text: "Detects common phishing lures such as login, verify, account, and payment." },
  { icon: <Gauge />, title: "Risk Scoring Engine", text: "Combines XGBoost probability, threat indicators, confidence, and severity." },
  { icon: <History />, title: "Detection History", text: "Stores scans for dashboard analysis, filtering, and audit review." },
];

const sampleUrls = [
  { label: "Safe Site", url: "https://www.google.com" },
  { label: "Shortened Alert", url: "http://bit.ly/paypal-login-alert" },
  { label: "Fake Login", url: "http://secure-paypal-login.example.com/verify-account" },
  { label: "IP URL", url: "http://185.199.108.153/login/verify" },
];

function formatNumber(value) {
  if (value === undefined || value === null) return "0";
  return new Intl.NumberFormat().format(value);
}

function severityFromScore(score, isPhishing = false) {
  if (isPhishing && score >= 85) return { label: "Phishing", color: "#fb7185", bg: "rgba(244, 63, 94, .16)", border: "rgba(251, 113, 133, .35)" };
  if (score >= 70) return { label: "High Risk", color: "#fb923c", bg: "rgba(249, 115, 22, .14)", border: "rgba(251, 146, 60, .32)" };
  if (score >= 45) return { label: "Suspicious", color: "#facc15", bg: "rgba(250, 204, 21, .13)", border: "rgba(250, 204, 21, .32)" };
  if (score >= 20) return { label: "Low Risk", color: "#38bdf8", bg: "rgba(56, 189, 248, .12)", border: "rgba(56, 189, 248, .28)" };
  return { label: "Safe", color: "#34d399", bg: "rgba(52, 211, 153, .13)", border: "rgba(52, 211, 153, .3)" };
}

function cleanFeatureName(name) {
  return String(name || "").replaceAll("_", " ");
}

function resultNarrative(result) {
  if (!result) return "";
  const primaryReasons = result.indicators?.slice(0, 3).join(", ");
  const scoreLine = `Risk score ${result.risk_score}/100 with ${result.confidence}% confidence.`;
  if (result.is_phishing) {
    return `${scoreLine} PhishGuard marked this URL as ${result.threat_level.toLowerCase()} because ${primaryReasons || "the XGBoost model detected URL patterns commonly found in phishing links"}. Treat this link as unsafe unless it is verified through a trusted source.`;
  }
  return `${scoreLine} PhishGuard did not find strong phishing indicators in the URL structure. This is a low-risk result, but users should still avoid entering passwords or payment details unless they trust the website.`;
}

function exportJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function Header() {
  return (
    <header className="sticky top-0 z-40 border-b border-white/10 bg-[#050816]/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
        <a href="#" className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg border border-cyan-300/30 bg-cyan-300/10 text-cyan-200 shadow-[0_0_30px_rgba(34,211,238,.18)]">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="text-lg font-black text-white">PhishGuard</div>
            <div className="text-xs font-semibold uppercase text-cyan-200/70">AI Threat Intelligence</div>
          </div>
        </a>
        <nav className="hidden items-center gap-1 md:flex">
          {["Scanner", "Features", "Dashboard", "Evidence"].map((item) => (
            <a key={item} href={`#${item.toLowerCase()}`} className="rounded-lg px-3 py-2 text-sm font-semibold text-slate-300 transition hover:bg-white/10 hover:text-white">
              {item}
            </a>
          ))}
          <a href="/docs" className="ml-2 rounded-lg border border-cyan-300/25 bg-cyan-300/10 px-4 py-2 text-sm font-bold text-cyan-100 transition hover:bg-cyan-300/20">
            API Docs
          </a>
        </nav>
      </div>
    </header>
  );
}

function CyberVisual() {
  const nodes = [
    [58, 22], [72, 35], [66, 54], [83, 61], [48, 69], [34, 48], [42, 30],
  ];
  return (
    <div className="relative hidden min-h-[520px] w-full overflow-hidden rounded-lg lg:flex lg:items-center lg:justify-center">
      <div className="cyber-grid absolute inset-3 rounded-lg border border-white/10" />
      <div className="hero-visual-sweep absolute inset-0" />
      <div className="hero-orbit absolute left-1/2 top-1/2 h-[420px] w-[420px] -translate-x-1/2 -translate-y-1/2 rounded-full" />
      <motion.div
        className="relative z-10 grid h-60 w-60 place-items-center rounded-lg border border-cyan-200/30 bg-cyan-200/10 shadow-[0_0_110px_rgba(34,211,238,.28)] backdrop-blur-md xl:h-72 xl:w-72"
        animate={{ y: [-8, 8, -8], rotate: [0, 1.5, 0] }}
        transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
      >
        <Shield size={112} className="text-cyan-100 drop-shadow-[0_0_18px_rgba(34,211,238,.7)] xl:h-36 xl:w-36" />
        <div className="absolute inset-5 rounded-lg border border-cyan-200/20" />
        <div className="absolute h-px w-80 bg-gradient-to-r from-transparent via-cyan-200 to-transparent" />
        <div className="absolute h-80 w-px bg-gradient-to-b from-transparent via-cyan-200/60 to-transparent" />
      </motion.div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        {nodes.slice(1).map((point, index) => (
          <line key={`${point[0]}-${point[1]}`} x1={nodes[index][0]} y1={nodes[index][1]} x2={point[0]} y2={point[1]} stroke="rgba(103,232,249,.26)" strokeWidth=".35" />
        ))}
        {nodes.map((point) => (
          <circle key={`${point[0]}-${point[1]}`} cx={point[0]} cy={point[1]} r="1.3" fill="rgba(125,249,255,.85)" />
        ))}
      </svg>
      <div className="absolute bottom-10 left-10 z-20 rounded-lg border border-white/10 bg-white/10 px-4 py-3 text-sm text-slate-200 backdrop-blur-xl">
        <div className="font-bold text-cyan-100">Threat graph active</div>
        <div className="mt-1 text-xs text-slate-400">URL intelligence nodes synchronized</div>
      </div>
      <div className="absolute right-8 top-10 z-20 rounded-lg border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm text-cyan-50 backdrop-blur-xl">
        <div className="font-black">XGBoost engine</div>
        <div className="mt-1 text-xs text-cyan-100/70">real-time scoring</div>
      </div>
    </div>
  );
}

function Scanner({ onResult }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Scan failed");
      onResult(data);
      window.location.hash = "result";
    } catch (err) {
      setError(err.message || "Unable to scan URL");
    } finally {
      setLoading(false);
    }
  }

  return (
    <motion.section
      id="scanner"
      className="glass-panel relative overflow-hidden rounded-lg p-4 md:p-5"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.15 }}
    >
      <div className="scan-line" />
      <form onSubmit={submit} className="relative z-10 flex flex-col gap-3 lg:flex-row">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-200/70" size={22} />
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="Enter a URL, e.g. https://example.com/login"
            className="h-16 w-full rounded-lg border border-white/10 bg-black/25 pl-12 pr-4 text-base font-semibold text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
            required
          />
        </div>
        <button
          disabled={loading}
          className="h-16 rounded-lg bg-gradient-to-r from-cyan-300 to-blue-500 px-7 font-black text-slate-950 shadow-[0_20px_50px_rgba(59,130,246,.28)] transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Scanning..." : "Scan Now"}
        </button>
      </form>
      <div className="relative z-10 mt-4 flex flex-wrap gap-2 text-xs font-bold text-slate-300">
        {["URL structure", "Shorteners", "Brand spoofing", "Encoded symbols", "XGBoost score"].map((tag) => (
          <span key={tag} className="rounded-lg border border-white/10 bg-white/5 px-3 py-2">{tag}</span>
        ))}
      </div>
      <div className="relative z-10 mt-4 border-t border-white/10 pt-4">
        <div className="text-xs font-black uppercase tracking-[.16em] text-slate-500">Try a sample</div>
        <div className="mt-3 flex flex-wrap gap-2">
          {sampleUrls.map((sample) => (
            <button
              key={sample.label}
              type="button"
              onClick={() => setUrl(sample.url)}
              className="rounded-lg border border-cyan-300/20 bg-cyan-300/10 px-3 py-2 text-xs font-black text-cyan-100 transition hover:bg-cyan-300/20"
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>
      {error && <div className="relative z-10 mt-4 rounded-lg border border-rose-400/35 bg-rose-500/10 px-4 py-3 text-sm font-semibold text-rose-100">{error}</div>}
    </motion.section>
  );
}

function Hero({ onResult, result }) {
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

function StatusTile({ icon, label, value, detail, color = "#67e8f9" }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[.06] p-4 backdrop-blur-md">
      <div className="flex items-center justify-between text-sm font-bold text-slate-400">
        <span>{label}</span>
        <span style={{ color }}>{React.cloneElement(icon, { size: 18 })}</span>
      </div>
      <div className="mt-3 break-words text-xl font-black leading-tight text-white xl:text-2xl">{value}</div>
      <div className="mt-1 text-xs font-semibold text-slate-500">{detail}</div>
    </div>
  );
}

function ResultPanel({ result }) {
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
          <ResponsiveContainer width="100%" height="100%">
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

function Features() {
  return (
    <section id="features" className="mx-auto mt-14 max-w-7xl px-5">
      <SectionHeading eyebrow="Capabilities" title="Premium URL threat intelligence in one workflow" text="A fast, URL-first security engine built for real-time scanning, evidence, and explainable results." />
      <div className="mt-7 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {featureCards.map((feature, index) => (
          <motion.div
            key={feature.title}
            className="glass-card rounded-lg p-5"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-80px" }}
            transition={{ delay: index * 0.035 }}
          >
            <div className="mb-5 grid h-11 w-11 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 text-cyan-100">
              {React.cloneElement(feature.icon, { size: 22 })}
            </div>
            <h3 className="font-black text-white">{feature.title}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-400">{feature.text}</p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

function SectionHeading({ eyebrow, title, text }) {
  return (
    <div>
      <div className="text-sm font-black uppercase text-cyan-200">{eyebrow}</div>
      <h2 className="mt-3 max-w-3xl text-3xl font-black text-white md:text-5xl">{title}</h2>
      <p className="mt-4 max-w-3xl text-base leading-7 text-slate-400">{text}</p>
    </div>
  );
}

function ModelEvidence({ metrics }) {
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
              <ResponsiveContainer width="100%" height="100%">
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

function EvidenceStat({ label, value }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
      <div className="text-2xl font-black text-white">{value}</div>
      <div className="mt-1 text-xs font-bold uppercase text-slate-500">{label}</div>
    </div>
  );
}

function ModelCard({ metrics }) {
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

function PrivacyNotice() {
  return (
    <section className="mx-auto mt-14 max-w-7xl px-5">
      <div className="glass-panel grid gap-5 rounded-lg p-6 md:grid-cols-[auto_1fr] md:items-center">
        <div className="grid h-14 w-14 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 text-cyan-100">
          <Lock size={26} />
        </div>
        <div>
          <h2 className="text-2xl font-black text-white">Privacy-first scanning</h2>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-400">
            PhishGuard stores submitted URLs only for local scan history and dashboard analytics. It does not ask for passwords, payment details, browser cookies, or account tokens. Avoid submitting private reset links or URLs containing sensitive access keys.
          </p>
        </div>
      </div>
    </section>
  );
}

function Dashboard({ stats, onClear }) {
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
            <ResponsiveContainer width="100%" height="100%">
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

function App() {
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);

  async function refreshStats() {
    try {
      const response = await fetch(`${API}/dashboard`);
      setStats(await response.json());
    } catch {
      setStats(null);
    }
  }

  async function clearHistory() {
    await fetch(`${API}/history`, { method: "DELETE" });
    await refreshStats();
  }

  useEffect(() => { refreshStats(); }, []);
  function handleResult(data) {
    setResult(data);
    refreshStats();
  }

  return (
    <div className="min-h-screen bg-[#050816] text-slate-100">
      <Header />
      <main>
        <Hero onResult={handleResult} result={result} />
        <ResultPanel result={result} />
        <Features />
        <ModelEvidence metrics={stats?.model_metrics || {}} />
        <ModelCard metrics={stats?.model_metrics || {}} />
        <PrivacyNotice />
        <Dashboard stats={stats} onClear={clearHistory} />
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
