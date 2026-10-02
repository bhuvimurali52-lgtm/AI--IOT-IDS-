# AI-Powered IoT Intrusion Detection — Local-Lab Real-Time Prototype

Defensive academic project: observe local/lab network traffic (or synthetic fixtures),
aggregate flows, extract features, detect anomalies with Isolation Forest, score risk,
alert, and visualize results.

> **Current status: Phase 8 — application hardening on the frozen Phase 7 baseline.**
> Phase 3 IsolationForest artifact is reused (no auto-retrain).

## Project objective

Build an IDS pipeline:

```text
Network Traffic → Scapy Capture → Flow Aggregation → Feature Extraction
→ Isolation Forest → NORMAL/ANOMALOUS → Risk Score → Alert → Dashboard
```

## Architecture

| Module | Role |
|--------|------|
| `app/capture` | Scapy live capture + synthetic fixtures |
| `app/features` | Flow aggregation + feature vectors |
| `app/detection` | Isolation Forest, risk scoring, predictor, live detector |
| `app/alerts` | High-risk alert generation (no blocking) |
| `app/database` | SQLite persistence |
| `app/api` | FastAPI endpoints |
| `app/dashboard` | Streamlit SOC dashboard (API client + charts) |
| `app/explainability` | Local baseline-occlusion explanations |
| `app/evaluation` | Controlled synthetic offline evaluation |
| `app/data` | Phase 2 CSV preprocessing (still available) |

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

## Streamlit dashboard

```bash
# 1) Start the Phase 5 API on the intended port (8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2) Start the SOC dashboard
streamlit run app/dashboard/streamlit_app.py --server.port 8502
```

`API_PORT` / `DASHBOARD_API_URL` default to port **8000**.

If `/api/model` returns **404**, an older Phase 3 uvicorn is still bound to 8000.
Identify it, then stop only that project process:

```powershell
netstat -ano | findstr :8000
# Confirm the PID is this project's uvicorn (ai-iot-ids\.venv\...\uvicorn ... --port 8000)
Stop-Process -Id <PID> -Force
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Shows SOC-style system health, anomaly rate, risk distribution, flow/risk
timelines, filters, auto-refresh, LIVE/SYNTHETIC controls, and model metadata.

Detects deviations from a learned baseline of network-flow behavior — not named
attack classes.

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
- Does **not** claim perfect attack detection
- Does **not** attribute exact attack names
- Is **not** production-grade protection
- Does **not** guarantee detection of every attack
- Synthetic fixtures are insufficient for production IDS claims
- Phase 7 metrics (accuracy / precision / recall / F1 / etc.) apply **only** to the
  controlled synthetic labeled evaluation set and must not be read as production
  IDS performance or named-attack detection rates

## Security posture

Observe → analyze → detect → log → alert.
No exploitation, credential theft, malware, evasion, or automatic host blocking.
