# Reproducibility Manifest

## Research Project

**Title:** A Blockchain-Assisted Cybersecurity Framework for AI-Based UAV Monitoring of Critical Infrastructure

**Conference:** MIPRO 2026

**Implementation:** Python-based research prototype integrating synthetic UAV telemetry, anomaly detection, authenticated PBFT consensus, certificate-backed ledger persistence, and simulated defensive responses.

## 1. Experimental Hardware

| Property | Configuration |
|---|---|
| Operating system | Microsoft Windows 11 Pro, 64-bit |
| OS version | 10.0.26300 |
| Processor | 12th Gen Intel Core i5-1235U |
| Physical cores | 10 |
| Logical processors | 12 |
| Memory | 15.44 GiB |
| AI acceleration | PyTorch CPU execution |

## 2. Software Environment

| Software | Version |
|---|---|
| Python | 3.11.6 |
| PyTorch | 2.15.0+cpu |
| NumPy | 2.4.6 |
| Pandas | 3.1.1 |
| scikit-learn | 1.9.1 |
| Cryptography | 50.0.2 |
| Matplotlib | 3.11.2 |
| Joblib | 1.6.0 |

A complete environment snapshot is stored in `results/experiment_dependencies.txt`.

## 3. Framework Configuration

- Four independent Ground Control Station processes: GCS_01, GCS_02, GCS_03 and GCS_04.
- Local TCP communication through ports 5001–5004.
- Simplified PBFT protocol with a quorum of three validators.
- Ed25519 digital signatures for authenticated communication and COMMIT certificates.
- SHA-256-based, hash-linked security-event ledger.
- Simulated policy-based defensive responses.

The implemented PBFT prototype is not a full production PBFT system and does not implement complete view-change functionality.

## 4. AI Model

The telemetry anomaly detector is a PyTorch autoencoder using four input features:

1. GPS drift (meters)
2. Signal-to-noise ratio (dB)
3. Packet transmission rate (Hz)
4. Packet loss ratio

The encoder uses a 4–8–3 architecture, while the decoder uses a 3–8–4 architecture. ReLU activation is applied in the hidden layers.

Training configuration:

- Training epochs: 100
- Batch size: 64
- Learning rate: 0.001
- Random seed: 42
- Optimizer: Adam
- Loss function: Mean squared reconstruction error
- Training data: Synthetic normal UAV telemetry
- Anomaly threshold: 99th percentile of normal validation reconstruction errors

The model is evaluated on synthetic normal and attack observations. Its results should not be interpreted as evidence of real-world attack-detection performance.

## 5. Experimental Evaluation

| Experiment | Configuration |
|---|---|
| PBFT consensus availability | Four, three and two online validators |
| Byzantine behavior tests | Conflicting, duplicate and malformed votes |
| Ledger security | Hash integrity and certificate tampering |
| Automated regression tests | 69 passing tests |
| Earlier end-to-end benchmark | 35 trials |
| Certified end-to-end benchmark | 30 trials |
| Certificate-processing overhead | 60 paired trials |
| Initial ledger histories | 0, 10 and 50 alert blocks |

## 6. Performance Results

**Earlier pipeline:** Mean end-to-end latency of 94.35 ms across 35 trials.

**Certified pipeline:** Mean end-to-end latency of 97.17 ms across 30 trials, with a 95th-percentile latency of 111.92 ms.

**Controlled certificate-processing overhead:** Mean additional local processing latency of 3.20 ms, 3.82 ms and 5.95 ms for 0, 10 and 50 pre-existing alert blocks, respectively.

All values were measured on localhost. The end-to-end pipeline measurements exclude one-time AI model initialization, physical UAV communication and real-world response actuation.

## 7. Reproduction Commands

Run the core unit tests:

```powershell
python -m pytest tests/test_pbft.py tests/test_replica.py tests/test_vote_guard.py tests/test_voting.py tests/test_pbft_adversarial.py tests/test_pbft_equivocation.py tests/test_pbft_byzantine_replica.py tests/test_pbft_adversarial_scheduling.py tests/test_ledger_store.py tests/test_response_engine.py tests/test_commit_certificate.py tests/test_certified_ledger.py -v
```

Run the certified end-to-end benchmark after starting all four GCS validators:

```powershell
python experiments/run_end_to_end_benchmark.py --trials 30 --output results/end_to_end_certified.csv
```

Run the controlled certificate-overhead experiment:

```powershell
python experiments/benchmark_certificate_overhead.py --trials 20 --blocks 0 10 50
```

Generate the overhead analysis:

```powershell
python experiments/analyze_certificate_overhead.py
```

**Reproducibility note:** The end-to-end benchmark appends records to a persistent local ledger. For stricter comparisons, initial ledger state, process restarts, system load and output-file handling should be controlled and recorded.

## 8. Source Version

**Repository:** `HarmonicBytes/uav-cybersecurity-framework`

**Git revision:** `e691e7867e2429c06dfd3ca8b31cb883e4a87d80`

The revision records the implementation state used for this reproducibility snapshot. Earlier experiment runs may have been executed using preceding revisions.

## 9. Limitations

The prototype uses synthetic telemetry, local TCP communication, a simplified PBFT implementation, and simulated defensive actions. Signed COMMIT certificates strengthen consensus evidence, but do not independently establish full Byzantine consensus safety or resistance to compromised signing keys.

The ledger is persisted locally rather than independently replicated across all validators. The reported latency measurements should not be generalized to operational UAV deployments without additional validation.