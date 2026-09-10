export function formatNumber(value) {
  if (value === undefined || value === null) return "0";
  return new Intl.NumberFormat().format(value);
}

export function severityFromScore(score, isPhishing = false) {
  if (isPhishing && score >= 85) {
    return { label: "Phishing", color: "#fb7185", bg: "rgba(244, 63, 94, .16)", border: "rgba(251, 113, 133, .35)" };
  }
  if (score >= 70) {
    return { label: "High Risk", color: "#fb923c", bg: "rgba(249, 115, 22, .14)", border: "rgba(251, 146, 60, .32)" };
  }
  if (score >= 45) {
    return { label: "Suspicious", color: "#facc15", bg: "rgba(250, 204, 21, .13)", border: "rgba(250, 204, 21, .32)" };
  }
  if (score >= 20) {
    return { label: "Low Risk", color: "#38bdf8", bg: "rgba(56, 189, 248, .12)", border: "rgba(56, 189, 248, .28)" };
  }
  return { label: "Safe", color: "#34d399", bg: "rgba(52, 211, 153, .13)", border: "rgba(52, 211, 153, .3)" };
}

export function cleanFeatureName(name) {
  return String(name || "").replaceAll("_", " ");
}

export function resultNarrative(result) {
  if (!result) return "";
  const primaryReasons = result.indicators?.slice(0, 3).join(", ");
  const scoreLine = `Risk score ${result.risk_score}/100 with ${result.confidence}% confidence.`;
  if (result.is_phishing) {
    return `${scoreLine} PhishGuard marked this URL as ${result.threat_level.toLowerCase()} because ${primaryReasons || "the XGBoost model detected URL patterns commonly found in phishing links"}. Treat this link as unsafe unless it is verified through a trusted source.`;
  }
  return `${scoreLine} PhishGuard did not find strong phishing indicators in the URL structure. This is a low-risk result, but users should still avoid entering passwords or payment details unless they trust the website.`;
}

export function exportJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
