import { useEffect, useState } from "react";

import { API } from "./lib/api";
import { Dashboard } from "./components/Dashboard";
import { Features } from "./components/Features";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { ModelCard } from "./components/ModelCard";
import { ModelEvidence } from "./components/ModelEvidence";
import { PrivacyNotice } from "./components/PrivacyNotice";
import { ResultPanel } from "./components/ResultPanel";

export function App() {
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

  function handleResult(data) {
    setResult(data);
    refreshStats();
  }

  useEffect(() => {
    refreshStats();
  }, []);

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
