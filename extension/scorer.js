// SCAMShield — local rule-based scorer: a browser subset re-implementation of
// scamshield/scorer.py (a subset of the Python engine's signals).
// The JS and Python signal lists are maintained separately.
// Runs entirely in the browser. Nothing is sent anywhere.

const WEIGHTS = {
  blocked_domain: 22, suspicious_tld: 8, deny_phrase: 5, allow_phrase: -4,
  shortener: 8, urgency: 6, time_pressure: 6, credential_request: 10,
  financial_request: 12, iban_detected: 10, crypto_address: 12,
  amount_present: 5, punycode_domain: 9, qr_request: 6,
  synergy_urgent_cred: 6, synergy_money_time: 6,
};

const SUSPICIOUS_TLDS = [".xyz", ".top", ".win", ".click", ".info", ".zip",
  ".country", ".gq", ".tk", ".ml", ".cf", ".buzz", ".rest", ".lol"];
const SHORTENERS = ["bit.ly", "tiny.cc", "t.co", "short.ly", "goo.gl",
  "is.gd", "cutt.ly", "ow.ly"];
const BLOCKED_DOMAINS = ["secure-bank-support.com", "amazon-prize.win",
  "paypal-verif.co", "impots-gouv.click"];

const DENYLIST = ["cliquez ici", "cliquez vite", "verifiez votre compte",
  "vérifiez votre compte", "compte suspendu", "compte bloqué", "gagné",
  "félicitations", "offre exclusive", "dernier avertissement", "remboursement",
  "mise à jour de sécurité", "reactivez", "réactivez", "carte cadeau"];
const ALLOWLIST = ["aucune action", "no rush", "pas d'urgence", "à bientôt",
  "merci pour votre confiance", "aucun incident", "rendez-vous confirmé"];

const RE = {
  url: /(https?:\/\/[^\s)<>]+)/gi,
  iban: /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/,
  btc: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/,
  amount: /(?:€|\$|£)\s?\d{2,6}(?:[.,]\d{2})?|\d{2,6}(?:[.,]\d{2})?\s?(?:eur|€|usd|dollars?|gbp)/i,
  qr: /\bqr\s?code\b|flasher.*qr|scanner.*qr/i,
};

const KW = {
  urgency: ["urgent", "immédiat", "immediat", "48h", "24h", "sans délai",
    "dernier avertissement", "compte suspendu"],
  time: ["aujourd'hui", "avant minuit", "dans l'heure", "sous 24h", "immédiatement"],
  cred: ["mot de passe", "password", "code sms", "code de vérification",
    "identifiant", "se connecter", "vérifier votre compte", "code reçu",
    "16 chiffres", "pièce d'identité"],
  money: ["paiement", "virement", "remboursement", "facture", "iban", "crypto",
    "bitcoin", "ethereum", "frais", "taxe", "amende", "droit", "règlement",
    "régler", "western union", "carte cadeau"],
};

const has = (t, list) => list.some((k) => t.includes(k));
const countHits = (t, list) => list.reduce((n, p) => (t.includes(p) ? n + 1 : n), 0);
const domainOf = (u) => {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ""; }
};
const baseOf = (d) => d.split(".").slice(-2).join(".");

export function scoreText(text) {
  const t = (text || "").toLowerCase();
  let score = 0;
  const reasons = [];
  const add = (w, label, sev) => { score += w; reasons.push({ label, sev }); };

  // URLs
  for (const m of text.matchAll(RE.url)) {
    const dom = domainOf(m[1]);
    if (!dom) continue;
    const base = baseOf(dom);
    if (BLOCKED_DOMAINS.includes(dom) || BLOCKED_DOMAINS.includes(base))
      add(WEIGHTS.blocked_domain, `Lien vers un domaine bloqué (${dom})`, "high");
    if (SHORTENERS.includes(base) || SHORTENERS.includes(dom))
      add(WEIGHTS.shortener, `Lien raccourci (${dom})`, "med");
    if (SUSPICIOUS_TLDS.some((tld) => dom.endsWith(tld)))
      add(WEIGHTS.suspicious_tld, `Extension de domaine suspecte (.${dom.split(".").pop()})`, "med");
    if (dom.split(".").some((l) => l.startsWith("xn--")))
      add(WEIGHTS.punycode_domain, `Domaine punycode / homographe (${dom})`, "high");
  }

  // Phrases
  const deny = countHits(t, DENYLIST);
  const allow = countHits(t, ALLOWLIST);
  if (deny > 0) add(deny * WEIGHTS.deny_phrase, `Expressions à risque (×${deny})`, "med");
  if (allow > 0) add(allow * WEIGHTS.allow_phrase, `Indices rassurants (×${allow})`, "low");

  // Social-engineering heuristics
  const urg = has(t, KW.urgency);
  const time = has(t, KW.time);
  const cred = has(t, KW.cred);
  const money = has(t, KW.money);
  if (urg) add(WEIGHTS.urgency, "Langage d'urgence", "med");
  if (time) add(WEIGHTS.time_pressure, "Pression temporelle", "med");
  if (cred) add(WEIGHTS.credential_request, "Demande d'identifiants / code", "high");
  if (money) add(WEIGHTS.financial_request, "Demande financière", "high");
  if (urg && cred) add(WEIGHTS.synergy_urgent_cred, "Combo urgence + identifiants", "high");
  if ((urg || time) && (money || RE.iban.test(text) || RE.btc.test(text) || RE.amount.test(text)))
    add(WEIGHTS.synergy_money_time, "Combo pression + argent", "high");

  // Hard signals
  if (RE.iban.test(text)) add(WEIGHTS.iban_detected, "IBAN détecté", "med");
  if (RE.btc.test(text)) add(WEIGHTS.crypto_address, "Adresse crypto détectée", "high");
  if (RE.amount.test(text)) add(WEIGHTS.amount_present, "Montant d'argent mentionné", "low");
  if (RE.qr.test(text)) add(WEIGHTS.qr_request, "Demande de scan QR code", "med");

  score = Math.max(0, Math.min(100, score));
  return { score: Math.round(score), reasons };
}

export function verdict(score) {
  if (score < 25) return { key: "safe", label: "SÛR" };
  if (score < 60) return { key: "doubt", label: "DOUTEUX" };
  return { key: "risky", label: "RISQUÉ" };
}
