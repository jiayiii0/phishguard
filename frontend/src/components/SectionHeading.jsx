export function SectionHeading({ eyebrow, title, text }) {
  return (
    <div>
      <div className="text-sm font-black uppercase text-cyan-200">{eyebrow}</div>
      <h2 className="mt-3 max-w-3xl text-3xl font-black text-white md:text-5xl">{title}</h2>
      <p className="mt-4 max-w-3xl text-base leading-7 text-slate-400">{text}</p>
    </div>
  );
}
