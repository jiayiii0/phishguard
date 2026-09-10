import { useState } from "react";
import { motion } from "framer-motion";
import { Search } from "lucide-react";

import { API } from "../lib/api";
import { sampleUrls } from "../lib/content";

export function Scanner({ onResult }) {
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
