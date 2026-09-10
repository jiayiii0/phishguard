import {
  BrainCircuit,
  Fingerprint,
  Gauge,
  Globe2,
  History,
  Layers3,
  Network,
  Zap,
} from "lucide-react";

export const featureCards = [
  { icon: <Zap />, title: "Real-Time URL Analysis", text: "Instant URL inspection without unsafe webpage crawling." },
  { icon: <BrainCircuit />, title: "XGBoost Threat Detection", text: "Primary ML classifier trained on large phishing and legitimate URL datasets." },
  { icon: <Layers3 />, title: "URL Structure Analysis", text: "Length, symbols, subdomains, entropy, encoding, and protocol checks." },
  { icon: <Globe2 />, title: "Domain Intelligence", text: "Hostname, TLD, brand impersonation, and typosquatting signals." },
  { icon: <Network />, title: "Redirect Pattern Detection", text: "Flags encoded characters, redirect-style paths, ports, and suspicious URL structure." },
  { icon: <Fingerprint />, title: "Suspicious Keyword Detection", text: "Detects common phishing lures such as login, verify, account, and payment." },
  { icon: <Gauge />, title: "Risk Scoring Engine", text: "Combines XGBoost probability, threat indicators, confidence, and severity." },
  { icon: <History />, title: "Detection History", text: "Stores scans for dashboard analysis, filtering, and audit review." },
];

export const sampleUrls = [
  { label: "Safe Site", url: "https://www.google.com" },
  { label: "Shortened Alert", url: "http://bit.ly/paypal-login-alert" },
  { label: "Fake Login", url: "http://secure-paypal-login.example.com/verify-account" },
  { label: "IP URL", url: "http://185.199.108.153/login/verify" },
];
