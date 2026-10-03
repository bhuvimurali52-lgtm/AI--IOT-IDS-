# AI-Powered IoT Intrusion Detection — Local-Lab Real-Time Prototype

An AI-powered IoT security monitoring prototype that detects anomalous network
behavior using an Isolation Forest model, assigns risk, generates alerts, provides
local explainability, and performs read-only Windows Firewall security posture
assessment through a SOC-style dashboard.

Defensive academic / competition prototype: observe authorized local/lab traffic
(or synthetic fixtures), extract a fixed 11-feature vector, detect deviations from
a learned baseline, score risk, alert, explain locally, and review host firewall
posture. It is **not** a production-grade IDS, **not** an enterprise SIEM
replacement, and **not** automatic attack prevention.

> **Current status: Phase 10 — final integration and security-intelligence demo
> on the frozen Phase 3–9 baseline.**
> IsolationForest artifact is reused (no auto-retrain). Phase 7 metrics remain
> controlled-synthetic only.

## Project overview

| | |
|---|---|
| **Problem** | IoT and lab networks need a transparent way to notice unusual flow behavior and review host firewall configuration without claiming named-attack detection or changing the host firewall. |
| **Proposed solution** | A local pipeline: capture or synthetic fixtures → 11-feature extraction → Isolation Forest → risk/alerts → local XAI → read-only Windows Firewall posture → SOC dashboard. |
| **Detection type** | Anomalous / deviation-from-baseline behavior, not comprehensive named-attack classification (DDoS, Mirai, malware families, etc.). |

## Architecture

```text
IoT Traffic
    ↓
Capture / Synthetic Generator
    ↓
Feature Extraction
    ↓
StandardScaler (embedded with the saved model)
    ↓
Isolation Forest
    ↓
Anomaly Score
    ↓
Risk Scoring
    ↓
Alert Engine
    ↓
XAI (local_baseline_occlusion)
    ↓
SOC Dashboard
```

```text
Windows Firewall
    ↓
Read-only Collector  (netsh advfirewall show allprofiles)
    ↓
Posture Analyzer
    ↓
Security Findings
    ↓
SOC Dashboard
```

Three distinct capabilities (do not conflate them):

- **A. Network anomaly detection** — Isolation Forest on flow features.
- **B. Explainability** — local baseline-occlusion of the anomaly score (not Shapley, not causal).
- **C. Host firewall posture assessment** — read-only configuration review. This is **not** an intrusion detector and does not block traffic.

## Major components / technology stack

| Module | Role |
|--------|------|
| `app/capture` | Scapy live capture + synthetic fixtures |
| `app/features` | Flow aggregation + 11-feature vectors |
| `app/detection` | Isolation Forest, risk scoring, predictor, live detector |
| `app/alerts` | High-risk alert generation (no blocking) |
| `app/database` | SQLite (`data/ids.db` by default) |
| `app/api` | FastAPI (`API_PORT` default **8000**) |
| `app/dashboard` | Streamlit SOC dashboard (port **8502**) |
| `app/explainability` | `local_baseline_occlusion` |
| `app/evaluation` | Controlled synthetic offline evaluation |
| `app/firewall` | Read-only Windows firewall posture checker |
| `app/data` | Phase 2 CSV preprocessing (still available) |

Stack: Python, FastAPI, Streamlit, scikit-learn IsolationForest, SQLite, Scapy (live only), Plotly.

## Project objective

Build an IDS **monitoring** pipeline:

```text
Network Traffic → Scapy Capture → Flow Aggregation → Feature Extraction
→ Isolation Forest → NORMAL/ANOMALOUS → Risk Score → Alert → Dashboard
```

## How the IDS works

1. Capture packets (live) **or** load synthetic flow fixtures (safe test).
2. Aggregate packets into flows (5-tuple key).
3. Extract a fixed numerical feature vector.
4. Score with an Isolation Forest trained on baseline/normal traffic.
5. Map anomaly score → risk (0–100) and severity.
6. Persist flows/alerts; show them on the dashboard.

**Important:** Isolation Forest finds deviations from a baseline. It does **not**
name attack types, attribute adversaries, or provide calibrated attack probabilities.

## Packet capture

- Class: `PacketCapture` in `app/capture/packet_capture.py`
- Modes: `IDS_MODE=synthetic` (no sniff) or `IDS_MODE=live` (Scapy)
- Configurable interface, duration, packet count, BPF filter
- Permission / missing-interface errors are handled without crashing the app

### Windows permission requirements

- Install [Npc](https://npcap.com/)
- Live sniffing often requires **Administrator**
- App starts without admin; live capture may fail until privileges/Npc are available

### Linux permission requirements

- Live sniffing often needs `CAP_NET_RAW` or root
- Prefer `IDS_MODE=synthetic` for privilege-free demos

## Flow aggregation

`app/features/flow_aggregator.py` keys flows by:

`src_ip, dst_ip, src_port, dst_port, protocol`

Tracks duration, packet/byte counts, rates, min/avg/max size, TCP flag counts.
Non-IP / incomplete packets are skipped safely.

## Feature list

Deterministic features (missing → `0.0`, never random):

- duration, packet_count, byte_count
- packets_per_second, bytes_per_second
- average_packet_size, min_packet_size, max_packet_size
- source_port, destination_port
- protocol (TCP=6, UDP=17, ICMP=1, OTHER=0)

## Isolation Forest

- Implemented in `app/detection/anomaly_detector.py`
- Configurable `contamination`, `n_estimators`, `random_state`
- Outputs `NORMAL` / `ANOMALOUS` plus `anomaly_score = -decision_function`
- Higher anomaly score ⇒ more anomalous (not an attack probability)

## Baseline training

```bash
# MODE B — synthetic fixtures (recommended for local demos)
python scripts/train_baseline.py --mode synthetic

# MODE A — live capture of local traffic (needs privileges)
python scripts/train_baseline.py --mode live
```

Saves: `models/anomaly_detector.joblib`

Synthetic training data is **fixtures only**, not real traffic.

## Risk scoring

`app/detection/risk.py`:

- Logistic map of anomaly score → base risk
- Small capped boost from extreme observed pps/bps
- Output clamped to **0–100**
- Severity (configurable): Low ≤29, Medium ≤59, High ≤79, else Critical

## Alert system

`app/alerts/` creates alerts for high-risk anomalies (threshold via `ALERT_RISK_THRESHOLD`).
Detection and logging only — **no blocking, disconnect, or offensive actions**.

## SQLite storage

Tables: `flows`, `alerts`, `model_metadata` in `DATABASE_PATH` (default `data/ids.db`).

## API endpoints

```text
GET  /health
GET  /ready
GET  /api/status
GET  /api/model
GET  /api/alerts
GET  /api/flows
GET  /api/explanation/{flow_id}
GET  /api/evaluation
GET  /api/firewall
POST /api/capture/start
POST /api/capture/stop
POST /api/detection/test
```

Inputs are validated. No arbitrary shell/command execution.

`GET /health` is liveness only (`status=ok`). `GET /ready` reports whether the
existing IsolationForest artifact can be loaded and the database is reachable.
Readiness **does not retrain** the model. Live capture / Npcap is not required
for readiness in synthetic mode.

Phase 4 live path: Scapy callback enqueues packets → background worker aggregates
flows → `FLOW_TIMEOUT_SECONDS` completes idle flows → `LiveDetector` scores once
with the saved IsolationForest (loaded once per session).

## Phase 7 — Controlled synthetic evaluation

Offline evaluation loads `models/anomaly_detector.joblib` **without retraining** and
scores a labeled synthetic dataset (same 11 features; `ground_truth` 0=normal,
1=anomalous). Labels are used **only after** inference.

Reported metrics (accuracy, precision, recall, F1, specificity, FPR, FNR,
anomaly detection rate, confusion matrix) describe performance on this
**controlled synthetic** set only — not production IDS effectiveness.

An offline **threshold analysis** sweeps anomaly-score cutoffs for research
visibility; it does **not** change the production IsolationForest threshold.

This remains anomaly / deviation detection, not named-attack classification.

## Phase 8 — Application hardening

Phase 8 is **application hardening** for a defensive IDS research/prototype. It is
**not** a production-security certification and does not change IsolationForest,
XAI, or Phase 7 evaluation methodology.

- **Public errors:** unexpected exceptions return a generic client message.
  Tracebacks, absolute filesystem paths, and secret-like fragments are redacted
  (`app/core/errors.py`). Technical detail is logged server-side.
- **Health vs readiness:** `/health` means the API process is alive.
  `/ready` means the existing model artifact can be loaded and SQLite is reachable.
  Neither endpoint retrains the detector.
- **CORS:** allowed origins come from `CORS_ALLOWED_ORIGINS` (default:
  `http://127.0.0.1:8502` and `http://localhost:8502`). Credentials are disabled.
  Wildcard origins are rejected in `APP_ENV=production`. This is not
  credentials-enabled `Access-Control-Allow-Origin: *`.
- **Timing:** `log_duration()` records local DEBUG timings for explanation and
  offline evaluation. These are not published as scientific benchmarks.
- **Secrets:** `.env` is not returned by the API. Configuration examples contain
  placeholders only.

Limitations: local lab prototype, no authn/authz gateway, SQLite file DB, joblib
model load still trusts a local artifact, live capture still needs Npcap/admin.

## XAI methodology

`GET /api/explanation/{flow_id}` explains a **persisted** flow with
`local_baseline_occlusion` against the loaded IsolationForest (no retrain).

Positive contribution: the feature moved the local score toward anomalous
behavior. This is a deterministic local approximation — **not** causal
attribution and **not** exact Shapley/SHAP values.

## Phase 9 — Read-only Windows Firewall posture

`GET /api/firewall` runs a **read-only** collector:

```text
netsh advfirewall show allprofiles
```

No `set` / `add` / `delete` / `reset` / `enable` / `disable`. No API input is
interpolated into a shell command. The checker is a host **configuration posture**
review, not an intrusion detector, and it does not modify or block traffic.

Dashboard copy: *Read-only security posture assessment — no firewall changes are performed.*

## Phase 10 — Security intelligence integration

The SOC dashboard composes existing APIs into one analyst workflow:

1. Security Intelligence Overview
2. Detection & Risk
3. Security Investigation
4. AI Explanation
5. Firewall Security Posture
6. Security Event Timeline (stored events only; no fabricated incidents)
7. IDS Evaluation (controlled synthetic)
8. Safe Demonstration (`POST /api/detection/test` + explanation + firewall GET)
9. System / Live Capture Status

The **Run Security Demonstration** button uses the existing synthetic fixture
path only (no packet injection, scanning, or firewall changes).

## Streamlit dashboard

```bash
# 1) Start the API on the intended port (8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2) Start the SOC dashboard
streamlit run app/dashboard/streamlit_app.py --server.port 8502
```

`API_PORT` / `DASHBOARD_API_URL` default to port **8000**. Dashboard port **8502**.

If `/api/model` returns **404**, an older uvicorn is still bound to 8000.
Identify it, then stop only that project process:

```powershell
netstat -ano | findstr :8000
# Confirm the PID is this project's uvicorn (ai-iot-ids\.venv\...\uvicorn ... --port 8000)
Stop-Process -Id <PID> -Force
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Dashboard capabilities: unified overview, investigation of existing flows,
local XAI, read-only firewall posture, event timeline, Phase 7 evaluation,
safe synthetic demonstration, and live/synthetic capture controls.

Detects deviations from a learned baseline of network-flow behavior — not named
attack classes. SYNTHETIC mode does not require Npcap. LIVE mode reports Npcap /
permission limits without blocking the rest of the dashboard.

## Safe test mode

```bash
python scripts/generate_test_traffic.py
python scripts/train_baseline.py --mode synthetic
# then API POST /api/detection/test or dashboard "Test detection"
```

Fixtures include normal-looking and high-rate unusual flow records.
Nothing is transmitted to external systems.

## Live capture mode

Set in `.env`:

```env
IDS_MODE=live
CAPTURE_INTERFACE=   # optional interface name
CAPTURE_DURATION=10
CAPTURE_PACKET_COUNT=100
FLOW_TIMEOUT_SECONDS=5
```

Live capture does **not** start automatically when Streamlit loads. Use Start Capture
only on systems/networks you are authorized to monitor. Records are tagged `mode=LIVE`
and are never mixed with synthetic fixtures as if they were live.

## Phase 2 CSV pipeline (still available)

```bash
python scripts/prepare_dataset.py --dataset data/raw/dataset.csv --target label
```

## Setup

```bash
cd ai-iot-ids
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
pip install -r requirements.txt
pip install -e ".[dev]"
Copy-Item .env.example .env
```

`pip install -e .` installs the project in editable mode so the `app` package imports reliably for Streamlit, FastAPI, scripts, and pytest.

## Run FastAPI

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Run tests

```bash
pytest
```

## Limitations (read carefully)

This local prototype:

- Detects deviations from a learned baseline of network-flow behavior
- Current IsolationForest was trained on **synthetic** normal baseline traffic
- Does **not** claim live traffic is accurately classified as DDoS, DoS, Mirai, etc.
- Does **not** claim 100% attack detection or comprehensive malware detection
- Does **not** attribute exact attack names
- Is **not** production-grade protection or an enterprise SIEM replacement
- Does **not** guarantee detection of every attack
- Does **not** automatically change or protect via Windows Firewall
- Synthetic fixtures are insufficient for production IDS claims
- Phase 7 metrics (accuracy / precision / recall / F1 / etc.) apply **only** to the
  controlled synthetic labeled evaluation set and must not be read as production
  IDS performance, real-world accuracy, or named-attack detection rates

## Ethical / safety boundaries

Observe → analyze → detect → log → alert → explain → (optional) read-only
firewall review.

No exploitation, credential theft, malware, evasion, packet injection, port
scanning, traffic manipulation, or automatic host blocking. Firewall assessment
never enables, disables, adds, deletes, or resets rules.

## Future scope

Possible later work (not implemented in Phase 10): stronger authentication,
richer telemetry sources, additional read-only host checks, and evaluation on
authorized labeled datasets. Any future blocking would require a separate,
explicitly scoped defensive design — it is out of scope here.

## Security posture

Observe → analyze → detect → log → alert.
No exploitation, credential theft, malware, evasion, or automatic host blocking.
