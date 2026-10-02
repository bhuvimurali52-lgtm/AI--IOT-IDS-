"""One-off Phase 3 model validation experiment (not part of product)."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from app.capture.synthetic import generate_synthetic_flow_records
from app.core.config import get_settings
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.predictor import Predictor
from app.detection.risk import (
    anomaly_score_to_base_risk,
    compute_risk_score,
    intensity_adjustment,
    risk_severity,
)
from app.features.extractor import flow_record_to_feature_dict, flow_records_to_matrix
from app.services.runtime import IDSRuntime


def main() -> None:
    model_path = Path("models/anomaly_detector.joblib")
    assert model_path.exists(), f"missing {model_path}"

    det = AnomalyDetector.load(model_path)
    print("=== MODEL ARTIFACT ===")
    print("path", model_path.resolve())
    print("is_fitted", det.is_fitted)
    print("n_training_samples", det.n_training_samples)
    print("n_estimators", det.n_estimators)
    print("contamination", det.contamination)
    print("random_state", det.random_state)
    print("feature_names", det.feature_names)
    print("scaler_type", type(det.scaler).__name__)
    print("model_type", type(det.model).__name__)
    print("scaler_mean_len", len(getattr(det.scaler, "mean_", [])))

    normal = generate_synthetic_flow_records(n_normal=25, n_anomalous=0)
    unusual = generate_synthetic_flow_records(n_normal=0, n_anomalous=25)
    xn, names = flow_records_to_matrix(normal)
    xu, _ = flow_records_to_matrix(unusual)

    print("\n=== FEATURE VECTOR / UNIQUENESS ===")
    print("feature_order", names)
    print("normal_shape", xn.shape, "unusual_shape", xu.shape)
    n_unique = len({tuple(np.round(r, 10)) for r in xn})
    u_unique = len({tuple(np.round(r, 10)) for r in xu})
    print("unique_normal_feature_rows", n_unique, "/", len(xn))
    print("unique_unusual_feature_rows", u_unique, "/", len(xu))
    print("example_normal_features", flow_record_to_feature_dict(normal[0]))
    print("example_unusual_features", flow_record_to_feature_dict(unusual[0]))
    print("unusual[0]==unusual[1]", bool(np.allclose(xu[0], xu[1])))
    print("unusual[0]==unusual[5]", bool(np.allclose(xu[0], xu[5])))

    buckets: dict[tuple, list[int]] = defaultdict(list)
    for i, row in enumerate(xu):
        buckets[tuple(np.round(row, 10))].append(i)
    dup_groups = {k: v for k, v in buckets.items() if len(v) > 1}
    print("unusual_duplicate_feature_groups", len(dup_groups))

    # Also check uniqueness after excluding source_port (to see rate-driven similarity)
    rate_keys = []
    for row in xu:
        # duration, packet_count, byte_count, pps, bps, avg, min, max, dst_port, protocol (exclude src_port idx 8)
        key = tuple(np.round(np.delete(row, 8), 8))
        rate_keys.append(key)
    print("unusual_unique_without_source_port", len(set(rate_keys)), "/", len(rate_keys))

    pred = Predictor(detector=det, database=None)
    normal_res = pred.predict_flows(normal)
    unusual_res = pred.predict_flows(unusual)

    def stats(results: list[dict], label: str) -> tuple[np.ndarray, int]:
        scores = np.array([r["anomaly_score"] for r in results], dtype=float)
        risks = np.array([r["risk_score"] for r in results], dtype=float)
        anoms = sum(1 for r in results if r["is_anomaly"])
        print(f"\n=== {label} ===")
        print("n", len(results))
        print(
            "anomaly_score min/max/mean/median",
            float(scores.min()),
            float(scores.max()),
            float(scores.mean()),
            float(np.median(scores)),
        )
        print("classified_anomalous", anoms)
        print(
            "risk min/max/mean",
            float(risks.min()),
            float(risks.max()),
            float(risks.mean()),
        )
        rounded = [round(s, 4) for s in scores]
        print("top_rounded_4dp_scores", Counter(rounded).most_common(8))
        print("exact_unique_scores", len(set(float(s) for s in scores)))
        return scores, anoms

    ns, na = stats(normal_res, "NORMAL GROUP A")
    us, ua = stats(unusual_res, "UNUSUAL GROUP B")

    print("\n=== SEPARATION ===")
    print("mean_unusual - mean_normal", float(us.mean() - ns.mean()))
    print("median_unusual - median_normal", float(np.median(us) - np.median(ns)))
    print("normal_max < unusual_min", float(ns.max()) < float(us.min()))
    overlap = ns.max() >= us.min() and us.max() >= ns.min()
    print("ranges_overlap", overlap)

    print("\n=== REPEATED 0.0483 INVESTIGATION ===")
    for i in range(min(8, len(unusual_res))):
        r = unusual_res[i]
        print(
            i,
            "exact",
            repr(r["anomaly_score"]),
            "r4",
            round(r["anomaly_score"], 4),
            "risk",
            r["risk_score"],
            "sev",
            r["severity"],
            "anom",
            r["is_anomaly"],
        )
        feats = r["features"]
        print(
            "  ",
            {
                k: feats[k]
                for k in [
                    "duration",
                    "packet_count",
                    "byte_count",
                    "packets_per_second",
                    "bytes_per_second",
                    "source_port",
                ]
            },
        )

    x5, _ = flow_records_to_matrix(unusual[:5])
    raw_df = det.decision_function(x5)
    raw_as = det.anomaly_scores(x5)
    print("decision_function", raw_df.tolist())
    print("anomaly_scores", raw_as.tolist())
    print(
        "matches_predictor",
        bool(
            np.allclose(
                raw_as, [unusual_res[i]["anomaly_score"] for i in range(5)]
            )
        ),
    )

    print("\n=== RISK / SEVERITY ===")
    settings = get_settings()
    for s in [-0.2, 0.0, 0.0483, 0.5, 1.0]:
        base = anomaly_score_to_base_risk(s)
        flow_hi = {"packets_per_second": 8000, "bytes_per_second": 9_600_000}
        flow_lo = {"packets_per_second": 10, "bytes_per_second": 1000}
        r_hi = compute_risk_score(s, flow_hi)
        r_lo = compute_risk_score(s, flow_lo)
        print(
            f"score={s}: base={base:.2f} "
            f"risk_hi={r_hi}/{risk_severity(r_hi, low_max=settings.risk_low_max, medium_max=settings.risk_medium_max, high_max=settings.risk_high_max)} "
            f"risk_lo={r_lo}/{risk_severity(r_lo, low_max=settings.risk_low_max, medium_max=settings.risk_medium_max, high_max=settings.risk_high_max)} "
            f"adj_hi={intensity_adjustment(flow_hi)}"
        )

    print("\n=== SAVE/LOAD CONSISTENCY ===")
    tmp = Path("models/_validation_reload.joblib")
    det.save(tmp)
    det2 = AnomalyDetector.load(tmp)
    s1 = det.anomaly_scores(xu)
    s2 = det2.anomaly_scores(xu)
    p1 = det.predict(xu)
    p2 = det2.predict(xu)
    print("scores_allclose", bool(np.allclose(s1, s2)))
    print("preds_equal", bool(np.array_equal(p1, p2)))
    tmp.unlink(missing_ok=True)

    print("\n=== PREPROCESSOR ARTIFACT ===")
    print(
        "standalone_preprocessor_exists",
        Path("models/baseline_preprocessor.joblib").exists(),
    )
    print("scaler_embedded_in_anomaly_detector_joblib", True)

    rt = IDSRuntime(get_settings())
    p = rt.get_predictor()
    print("runtime_model_path", Path(rt.settings.model_path).resolve())
    print("runtime_detector_loaded", p.detector is not None and p.detector.is_fitted)
    print("runtime_n_training", p.detector.n_training_samples if p.detector else None)


if __name__ == "__main__":
    main()
