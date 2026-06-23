import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, AlertTriangle, BarChart3, BrainCircuit, CheckCircle2, Database, FileText, Lock, Radar, Search, ShieldCheck, Zap } from "lucide-react";
import "./styles.css";

const API = "/api/v1";

function tone(score) {
  if (score >= 70) return { label: "High Risk", text: "text-red-600", bg: "bg-red-50", border: "border-red-200", fill: "#dc2626" };
  if (score >= 35) return { label: "Medium Risk", text: "text-amber-600", bg: "bg-amber-50", border: "border-amber-200", fill: "#d97706" };
  return { label: "Low Risk", text: "text-emerald-600", bg: "bg-emerald-50", border: "border-emerald-200", fill: "#16a34a" };
}

function Header() {
  return (
    <header className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5">
      <div className="flex items-center gap-3">
        <div className="grid h-11 w-11 place-items-center rounded-2xl bg-gradient-to-br from-cyber to-aqua text-white shadow-soft">
          <ShieldCheck size={24} />
        </div>
        <div>
          <div className="text-xl font-black tracking-tight text-ink">PhishGuard</div>
          <div className="text-xs font-bold uppercase tracking-[0.18em] text-slate-500">XGBoost Threat Detection</div>
        </div>
      </div>
      <nav className="hidden items-center gap-2 md:flex">
        <a className="rounded-lg px-3 py-2 text-sm font-bold text-slate-600 hover:bg-white" href="#scan">Scanner</a>
        <a className="rounded-lg px-3 py-2 text-sm font-bold text-slate-600 hover:bg-white" href="#dashboard">Dashboard</a>
        <a className="rounded-lg px-3 py-2 text-sm font-bold text-slate-600 hover:bg-white" href="/docs">API Docs</a>
      </nav>
    </header>
  );
}

function Metric({ icon, label, value, detail }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-bold text-slate-500">{label}</div>
        <div className="grid h-9 w-9 place-items-center rounded-xl bg-blue-50 text-cyber">{icon}</div>
      </div>
      <div className="mt-3 text-3xl font-black text-ink">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{detail}</div>
    </div>
  );
}

function ScanForm({ onResult }) {
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
    <section id="scan" className="mx-auto max-w-5xl rounded-2xl border border-slate-200 bg-white p-4 shadow-soft">
      <form className="flex flex-col gap-3 md:flex-row" onSubmit={submit}>
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={20} />
          <input
            className="h-14 w-full rounded-xl border border-slate-300 pl-12 pr-4 text-base outline-none focus:border-cyber focus:ring-4 focus:ring-blue-100"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="Enter a URL, e.g. https://example.com/login"
            required
          />
        </div>
        <button className="h-14 rounded-xl bg-gradient-to-r from-cyber to-aqua px-7 font-black text-white shadow-lg shadow-blue-200 disabled:opacity-60" disabled={loading}>
          {loading ? "Scanning..." : "Scan URL"}
        </button>
      </form>
      <div className="mt-3 flex flex-wrap justify-center gap-3 text-xs font-bold text-slate-500">
        <span>URL structure</span><span>Shorteners</span><span>Homograph checks</span><span>Brand impersonation</span><span>SHAP factors</span>
      </div>
      {error && <div className="mt-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">{error}</div>}
    </section>
  );
}

function Workflow() {
  const cards = [
    { icon: <Search />, title: "URL Input", text: "Paste a suspicious URL into a simple real-time scanning workflow." },
    { icon: <Radar />, title: "Feature Extraction", text: "URL structure, HTTPS, shortener, brand, homograph, DNS and WHOIS related features." },
    { icon: <BrainCircuit />, title: "XGBoost Prediction", text: "The primary machine learning engine classifies phishing risk." },
    { icon: <BarChart3 />, title: "SHAP Explanation", text: "Top factors are shown so users can understand the verdict." },
  ];
  return (
    <section className="mx-auto mt-10 grid max-w-7xl gap-4 md:grid-cols-4">
      {cards.map((card) => (
        <div key={card.title} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <div className="grid h-12 w-12 place-items-center rounded-2xl bg-blue-50 text-cyber">{card.icon}</div>
          <h3 className="mt-4 font-black text-ink">{card.title}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-600">{card.text}</p>
        </div>
      ))}
    </section>
  );
}

function ResultPanel({ result }) {
  if (!result) {
    return (
      <section id="result" className="mx-auto mt-8 max-w-5xl rounded-2xl border border-dashed border-slate-300 bg-white/70 p-10 text-center">
        <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl bg-blue-50 text-cyber"><Activity size={32} /></div>
        <h2 className="mt-4 text-2xl font-black text-ink">No scan result yet</h2>
        <p className="mt-2 text-slate-600">Enter a website URL above to run the XGBoost phishing detection workflow.</p>
      </section>
    );
  }
  const risk = tone(result.risk_score);
  const chartData = [{ name: "Risk", value: result.risk_score }, { name: "Remaining", value: Math.max(100 - result.risk_score, 0) }];
  return (
    <section id="result" className="mx-auto mt-8 grid max-w-7xl gap-5 lg:grid-cols-[1.1fr_.9fr]">
      <div className={`rounded-2xl border ${risk.border} ${risk.bg} p-6 shadow-soft`}>
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <div className={`inline-flex rounded-full bg-white px-3 py-1 text-sm font-black ${risk.text}`}>{risk.label}</div>
            <h2 className="mt-4 text-3xl font-black text-ink">{result.is_phishing ? "Phishing website detected" : "Website appears safe"}</h2>
            <p className="mt-2 break-all text-slate-600">{result.url}</p>
          </div>
          <div className="rounded-xl bg-white p-5 text-center shadow-soft">
            <div className="text-sm font-bold text-slate-500">Risk Score</div>
            <div className={`text-5xl font-black ${risk.text}`}>{result.risk_score}</div>
            <div className="text-sm text-slate-500">Confidence {result.confidence}%</div>
          </div>
        </div>
        <div className="mt-6 grid gap-3 md:grid-cols-3">
          <Metric icon={<BrainCircuit size={18} />} label="Prediction" value={result.result} detail="XGBoost classifier" />
          <Metric icon={<Database size={18} />} label="Hostname" value={result.hostname || "N/A"} detail="Parsed domain" />
          <Metric icon={<AlertTriangle size={18} />} label="Indicators" value={result.indicators.length} detail="Risk signals" />
        </div>
        <div className="mt-6 rounded-xl bg-white p-5">
          <h3 className="font-black text-ink">Detected Indicators</h3>
          <div className="mt-3 grid gap-2">
            {(result.indicators.length ? result.indicators : ["No high-risk URL indicator was detected."]).map((item) => (
              <div key={item} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-semibold text-slate-700">{item}</div>
            ))}
          </div>
        </div>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-soft">
        <h3 className="text-xl font-black text-ink">Explainable AI Factors</h3>
        <p className="mt-1 text-sm text-slate-500">Top factors influencing the XGBoost risk result.</p>
        <div className="mt-5 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={chartData} innerRadius={62} outerRadius={86} dataKey="value" startAngle={90} endAngle={-270}>
                <Cell fill={risk.fill} /><Cell fill="#e2e8f0" />
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="space-y-3">
          {result.shap_factors.slice(0, 6).map((factor) => (
            <div key={factor.feature} className="rounded-xl border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-3">
                <div className="font-black text-ink">{factor.feature.replaceAll("_", " ")}</div>
                <div className={factor.direction === "raises risk" ? "font-black text-red-600" : "font-black text-emerald-600"}>{factor.direction}</div>
              </div>
              <div className="mt-1 text-sm text-slate-500">value: {String(factor.value)} | impact: {factor.impact}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Dashboard({ stats }) {
  const riskData = useMemo(() => [
    { name: "Low", value: stats?.risk_buckets?.low || 0 },
    { name: "Medium", value: stats?.risk_buckets?.medium || 0 },
    { name: "High", value: stats?.risk_buckets?.high || 0 },
  ], [stats]);
  return (
    <section id="dashboard" className="mx-auto mt-10 max-w-7xl">
      <div className="mb-4 flex items-end justify-between gap-4">
        <div><h2 className="text-3xl font-black text-ink">Threat Dashboard</h2><p className="mt-1 text-slate-600">Scan statistics, model evidence, and stored results.</p></div>
        <a className="rounded-xl bg-white px-4 py-3 text-sm font-black text-cyber shadow-soft" href="/docs">Open REST API Docs</a>
      </div>
      <div className="grid gap-4 md:grid-cols-4">
        <Metric icon={<Activity size={18} />} label="Total Scans" value={stats?.total_scans || 0} detail="Stored in database" />
        <Metric icon={<AlertTriangle size={18} />} label="Phishing" value={stats?.phishing_detected || 0} detail="Risk detections" />
        <Metric icon={<CheckCircle2 size={18} />} label="Safe" value={stats?.safe_detected || 0} detail="Safe detections" />
        <Metric icon={<Zap size={18} />} label="Avg Risk" value={stats?.average_risk_score || 0} detail="0-100 score" />
      </div>
      <div className="mt-5 grid gap-5 lg:grid-cols-[.85fr_1.15fr]">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <h3 className="font-black text-ink">Risk Distribution</h3>
          <div className="mt-4 h-64"><ResponsiveContainer width="100%" height="100%"><BarChart data={riskData}><XAxis dataKey="name" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="value" fill="#1d4ed8" radius={[8, 8, 0, 0]} /></BarChart></ResponsiveContainer></div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
          <h3 className="font-black text-ink">Recent Scans</h3>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500"><tr><th className="py-2">URL</th><th>Result</th><th>Risk</th><th>Confidence</th></tr></thead>
              <tbody>{(stats?.recent_scans || []).map((scan) => (<tr key={scan.id} className="border-t border-slate-100"><td className="max-w-sm break-all py-3 pr-3 font-semibold">{scan.url}</td><td className={scan.is_phishing ? "font-black text-red-600" : "font-black text-emerald-600"}>{scan.result}</td><td>{scan.risk_score}</td><td>{scan.confidence}%</td></tr>))}</tbody>
            </table>
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
  useEffect(() => { refreshStats(); }, []);
  function handleResult(data) { setResult(data); refreshStats(); }
  return (
    <div>
      <Header />
      <main className="px-5 pb-14">
        <section className="mx-auto max-w-7xl rounded-3xl border border-blue-100 bg-gradient-to-br from-sky-400 via-blue-600 to-cyan-500 p-8 text-center text-white shadow-soft md:p-12">
          <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-white/30 bg-white/15"><ShieldCheck size={36} /></div>
          <h1 className="mt-5 text-4xl font-black tracking-tight md:text-6xl">PhishGuard</h1>
          <p className="mx-auto mt-4 max-w-3xl text-lg font-medium text-blue-50">Real-time phishing website detection powered by XGBoost, explainable AI, and lightweight URL intelligence.</p>
          <div className="mt-6 flex flex-wrap justify-center gap-3 text-sm font-black"><span className="rounded-full border border-white/25 bg-white/15 px-4 py-2">XGBoost Primary Engine</span><span className="rounded-full border border-white/25 bg-white/15 px-4 py-2">PhishTank Dataset Pipeline</span><span className="rounded-full border border-white/25 bg-white/15 px-4 py-2">0-100 Risk Score</span></div>
        </section>
        <div className="-mt-7"><ScanForm onResult={handleResult} /></div>
        <Workflow />
        <ResultPanel result={result} />
        <Dashboard stats={stats} />
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
