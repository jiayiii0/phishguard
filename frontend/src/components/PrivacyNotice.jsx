import { Lock } from "lucide-react";

export function PrivacyNotice() {
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
