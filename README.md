# UAV Cybersecurity Framework

**A Blockchain-Assisted Cybersecurity Framework for AI-Based UAV Monitoring of Critical Infrastructure**

Python research prototype demonstrating an integrated pipeline for **telemetry-based anomaly detection**, **authenticated security alerts**, **PBFT-inspired consensus**, **certificate-backed blockchain replication**, and **simulated defensive response**.

> **Research prototype — not a deployed UAV security product.** The experiments use synthetic UAV telemetry and four GCS validator processes communicating locally. The consensus implementation is a simplified PBFT-inspired protocol, not a production-grade Byzantine fault-tolerant service. Defensive responses are recorded simulations, not flight-control commands.

## Overview

The framework processes an anomalous telemetry observation through the following stages:

1. **Telemetry and AI detection:** A PyTorch autoencoder models normal behavior over four features: GPS drift (m), signal-to-noise ratio (dB), packet rate (Hz), and packet loss ratio. A reconstruction error exceeding a learned threshold produces an anomaly alert.
2. **Authenticated communication:** Ed25519-signed messages carry the alert to the authorized Ground Control Station (GCS) validators.
3. **Distributed agreement:** Four independent GCS processes exchange authenticated PBFT-inspired messages. The prototype requires a quorum of at least **three of four validators**.
4. **Cryptographic evidence:** Original signed COMMIT votes form a verifiable consensus certificate attached to the security-event record.
5. **Replicated persistence:** Four independent GCS ledgers receive certified, SHA-256 hash-linked blocks. The implementation checks block integrity, predecessor linkage, and COMMIT certificates.
6. **Simulated response:** The response engine records operator notification, increased telemetry monitoring, and a request for manual UAV inspection.

The project also evaluates the latency of each processing stage and the cost of verifying historical ledger certificates. An in-process, verified-state cache accelerates repeated ledger-status queries while an explicit full-history audit remains available.

## Repository layout

```text
config/                  Validator configuration; local private keys are excluded from Git
experiments/             Benchmarks, integrations, and analysis scripts
figures/                 Generated experimental plots and figures
src/ai/                  Synthetic telemetry and autoencoder model
src/blockchain/          Authentication, PBFT prototype, certificates, and replication
src/security/            Simulated security-response processing
tests/                   Unit, adversarial, and replication regression tests
REPRODUCIBILITY.md       Experimental environment and earlier reproducibility snapshot
requirements.txt         Python dependencies
```

The `results/` directory holds locally generated models, datasets, CSV files, and persistent ledgers. **Not all generated experimental artifacts are necessarily committed**; regenerate or provide these separately when reproducing the study.

## Requirements

The evaluated workstation used Windows 11 Pro, Python **3.11.6**, an Intel Core **i5-1235U**, approximately **16 GB RAM**, and CPU-based PyTorch execution. The four GCS validators run as separate local processes and use TCP ports **5001–5004**.

See [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) for a software-environment snapshot and historical experimental setup. That document is an **earlier snapshot** and may not reflect the final test count or fully replicated ledger implementation.

## Setup (Windows PowerShell)

Clone and create a virtual environment:

```powershell
git clone https://github.com/HarmonicBytes/uav-cybersecurity-framework.git
cd uav-cybersecurity-framework
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Validator keys and configuration

The application expects `config/validators.json` and corresponding local Ed25519 private keys under `config/keys/`. The private-key directory is intentionally excluded from Git.

**Never commit or publish private keys.** Create fresh, mutually consistent key pairs and configure the public keys in the validator registry before starting the validators. Consult the key-generation/configuration code in the repository for the expected PEM and registry formats; keys from the author's experimental environment are not distributed. A clean clone may therefore require key setup and model training before it can execute the full pipeline.

**Important:** Previously persisted ledger certificates were signed by an earlier key set. Changing validator keys can make those historical certificates unverifiable under the new registry; use a separate, fresh test ledger for a new key set, and preserve archival experiments separately.

## Start the four GCS validators

Open **four PowerShell terminals**, activate the same virtual environment in each, and run one command per terminal:

```powershell
python src\blockchain\node.py --id GCS_01 --port 5001
```

```powershell
python src\blockchain\node.py --id GCS_02 --port 5002
```

```powershell
python src\blockchain\node.py --id GCS_03 --port 5003
```

```powershell
python src\blockchain\node.py --id GCS_04 --port 5004
```

Keep them running during network experiments. Stop them with **Ctrl+C**.

## AI model

The anomaly detector uses a four-input PyTorch autoencoder with architecture **4–8–3–8–4**, trained on **synthetic normal UAV telemetry**. The decision threshold is based on the **99th percentile of normal reconstruction errors**. A high reconstruction error represents an anomalous observation, **not proof of a cyberattack**.

Training and model artifacts are handled by the scripts in `src/ai/`; the end-to-end benchmark expects the trained model and supporting preprocessing artifacts to exist locally. The original experiments used a synthetic dataset and do not establish real-world UAV attack-detection accuracy.

## Run tests

```powershell
python -m pytest tests -q
```

The final local validation reported **80 passing tests**, including authentication, PBFT-related behavior, certificate verification, ledger replication, and selected adversarial cases. The passing count is specific to the evaluated source revision and environment.

## Run an end-to-end experiment

After configuring local validator keys, preparing the AI model, and starting all four GCS processes:

```powershell
python experiments\run_end_to_end_benchmark.py --trials 1 --output results\smoke_test.csv
```

For a 30-trial evaluation:

```powershell
python experiments\run_end_to_end_benchmark.py --trials 30 --output results\final_end_to_end_30_trials.csv
```

**Note:** Successful runs **append persistent security-event blocks** to the central and GCS ledgers. Ledger height, process warm-up, machine load, and restart state affect latency. Back up existing ledgers before resetting anything, and record starting ledger heights for comparisons.

### Analyze the 30-trial CSV

```powershell
python experiments\analyze_final_mipro_benchmark.py --input results\final_end_to_end_30_trials.csv
```

Analysis outputs are written under `results/final_mipro_analysis/` and may include tables and publication figures, depending on the current analysis script.

## Measured research results

The final **local** 30-trial run reported:

| Metric | Result |
|---|---:|
| Completed trials | 30 / 30 |
| Mean total pipeline latency | 413.18 ms |
| Mean AI inference latency | 1.79 ms |
| Mean authentication latency | 3.58 ms |
| Mean PBFT consensus-stage latency | 44.69 ms |
| Mean central persistence latency | 49.87 ms |
| Mean GCS replication latency | 268.73 ms |
| Mean simulated response latency | 42.89 ms |
| Total latency standard deviation | 52.82 ms |
| Total latency 95th percentile | 508.93 ms |

Initial PyTorch model loading was **excluded** from these pipeline figures. All four validators replicated the certified events during the tested trials. The observed 100% success rate is limited to this experimental configuration and is not a general reliability guarantee.

### Ledger-status verification microbenchmark

At a **66-block** ledger height, the reported local measurements were:

| Status-verification method | Mean latency |
|---|---:|
| Full historical certificate audit | 46.1684 ms |
| Cached verified-state query | 0.3248 ms |
| Observed speedup | 142.15× |

This comparison concerns **repeated ledger-status queries**, not the complete end-to-end pipeline. The cached path relies on prior successful verification and a comparison of ledger and registry content fingerprints; a full audit still verifies historical certificates.

## Security and experimental limitations

- **Synthetic data:** The telemetry and attack labels are simulated; field validation on real UAV data remains future work.
- **Local testbed:** Four validator processes run on one workstation; realistic wireless/network delays are not represented.
- **Simplified PBFT:** The implementation does not provide full production Byzantine fault-tolerance guarantees or complete view-change support.
- **Simulated actions:** Operator alerts, monitoring changes, and inspection requests are recorded, not physically actuated on UAVs.
- **Ledger cache assumptions:** Fingerprinting and in-process locks do not prevent rollback attacks or all cross-process/concurrent file-replacement races.
- **Model compression:** Quantization results must be interpreted as measured; a quantized format is not necessarily smaller or faster on this CPU.
- **No physical UAV link or deployed smart contract is established by these experiments.**

The repository is intended for **academic research and reproducibility**, not operational protection of critical infrastructure.

## Reproducibility and citing the software

- Main source repository: https://github.com/HarmonicBytes/uav-cybersecurity-framework
- Experimental notes: [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md)
- For scholarly references, cite the repository at a **specific commit or release tag** used for the reported experiments. The repository's `main` branch may change.
- Paper: *A Blockchain-Assisted Cybersecurity Framework for AI-Based UAV Monitoring of Critical Infrastructure* (MIPRO research manuscript).

## License

No license is declared in this repository unless a `LICENSE` file is added. Public visibility alone does not grant reuse rights beyond those provided by applicable law. Contact the repository owner for licensing questions.
