import { ShieldCheck } from "lucide-react";

export function Header() {
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
