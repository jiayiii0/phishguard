import { motion } from "framer-motion";
import { Shield } from "lucide-react";

export function CyberVisual() {
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
