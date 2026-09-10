import React from "react";

export function StatusTile({ icon, label, value, detail, color = "#67e8f9" }) {
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
