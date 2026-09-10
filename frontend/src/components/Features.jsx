import React from "react";
import { motion } from "framer-motion";

import { featureCards } from "../lib/content";
import { SectionHeading } from "./SectionHeading";

export function Features() {
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
