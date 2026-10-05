"""Dashboard navigation labels (UI only; does not control IDS_MODE)."""

NAV_OVERVIEW = "▣ Overview"
NAV_THREAT = "⚠ Threat Detection"
NAV_INVESTIGATION = "🔍 Investigation"
NAV_XAI = "🧠 AI Explainability"
NAV_FIREWALL = "🔥 Firewall Posture"
NAV_EVALUATION = "📊 Evaluation"
NAV_SYSTEM = "⚙ System"
NAV_PAGES = (
    NAV_OVERVIEW,
    NAV_THREAT,
    NAV_INVESTIGATION,
    NAV_XAI,
    NAV_FIREWALL,
    NAV_EVALUATION,
    NAV_SYSTEM,
)
AUTO_REFRESH_PAGES = {NAV_OVERVIEW, NAV_THREAT}
