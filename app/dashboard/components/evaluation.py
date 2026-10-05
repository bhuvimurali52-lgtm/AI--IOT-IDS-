"""Controlled synthetic evaluation panel for the SOC dashboard."""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
import streamlit as st

logger = logging.getLogger(__name__)


def render_evaluation_panel(client: Any, *, api_online: bool) -> None:
    """Controlled synthetic offline evaluation section."""
    from app.dashboard.charts import threshold_analysis_figure

    st.markdown("### CONTROLLED SYNTHETIC EVALUATION")
    st.subheader("IDS Evaluation")
    st.warning(
        "These metrics measure performance on the controlled synthetic "
        "evaluation dataset and should not be interpreted as production "
        "IDS performance."
    )
    st.caption(
        "Ground-truth labels (normal vs anomalous) are used only after "
        "inference. This is anomaly/deviation evaluation — not named-attack "
        "classification."
    )

    c1, c2 = st.columns(2)
    with c1:
        run = st.button(
            "Run controlled evaluation",
            key="eval_run_btn",
            disabled=not api_online,
            use_container_width=True,
        )
    with c2:
        refresh_cache = st.button(
            "Fetch cached / latest evaluation",
            key="eval_fetch_btn",
            disabled=not api_online,
            use_container_width=True,
        )

    if run:
        try:
            st.session_state["eval_result"] = client.evaluation(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Evaluation failed")
            st.error("Unable to run evaluation.")
            st.caption(str(exc))
            return
    elif refresh_cache:
        try:
            st.session_state["eval_result"] = client.evaluation(force=False)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Evaluation fetch failed")
            st.error("Unable to fetch evaluation.")
            st.caption(str(exc))
            return

    result = st.session_state.get("eval_result")
    if not result:
        st.info("Run controlled evaluation to populate metrics.")
        return

    ds = result.get("dataset") or {}
    pred = result.get("predictions") or {}
    cm = result.get("confusion_matrix") or {}
    mets = result.get("metrics") or {}

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Dataset size", ds.get("total", 0))
    m2.metric("Normal (ground truth)", ds.get("normal", 0))
    m3.metric("Anomalous (ground truth)", ds.get("anomalous", 0))
    m4.metric("Predicted anomalous", pred.get("anomalous", 0))

    st.markdown("**Confusion matrix**")
    st.write(
        f"TN={cm.get('tn', 0)} | FP={cm.get('fp', 0)} | "
        f"FN={cm.get('fn', 0)} | TP={cm.get('tp', 0)}"
    )

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Accuracy", f"{float(mets.get('accuracy', 0)):.4f}")
    k2.metric("Precision", f"{float(mets.get('precision', 0)):.4f}")
    k3.metric("Recall", f"{float(mets.get('recall', 0)):.4f}")
    k4.metric("F1", f"{float(mets.get('f1', 0)):.4f}")
    k5, k6, k7, k8 = st.columns(4)
    k5.metric("Specificity", f"{float(mets.get('specificity', 0)):.4f}")
    k6.metric("FPR", f"{float(mets.get('false_positive_rate', 0)):.4f}")
    k7.metric("FNR", f"{float(mets.get('false_negative_rate', 0)):.4f}")
    k8.metric(
        "Anomaly detection rate",
        f"{float(mets.get('anomaly_detection_rate', 0)):.4f}",
    )

    thr_rows = result.get("threshold_analysis") or []
    if thr_rows:
        st.markdown("**Offline threshold analysis**")
        st.caption(
            "Explores alternate anomaly-score cutoffs on the same scores. "
            "Does not change the production IsolationForest threshold."
        )
        st.plotly_chart(
            threshold_analysis_figure(thr_rows),
            use_container_width=True,
            key="eval_threshold_chart",
        )
        show = pd.DataFrame(thr_rows)
        st.dataframe(
            show,
            use_container_width=True,
            hide_index=True,
            key="eval_threshold_table",
        )

    if result.get("limitation"):
        st.caption(str(result["limitation"]))
