
from pathlib import Path

import numpy as np
import pandas as pd


# Configuration for reproducible experiments
RANDOM_SEED = 42
SAMPLES_PER_SCENARIO = 1000

SCENARIOS = [
    "normal",
    "gps_spoofing",
    "rf_jamming",
    "network_flooding",
]


def generate_telemetry(
    samples_per_scenario=SAMPLES_PER_SCENARIO,
    seed=RANDOM_SEED,
):
    """Generate labeled synthetic UAV telemetry observations."""

    if samples_per_scenario <= 0:
        raise ValueError("samples_per_scenario must be positive")

    rng = np.random.default_rng(seed)
    records = []

    for scenario in SCENARIOS:
        for sample_id in range(samples_per_scenario):

            # Normal UAV operation baseline
            gps_drift = max(0.0, rng.normal(0.5, 0.2))
            snr = np.clip(rng.normal(35.0, 3.0), 0, 60)
            packet_rate = max(0.0, rng.normal(12.0, 2.0))
            packet_loss = np.clip(
                rng.normal(0.01, 0.005), 0, 1
            )

            # Inject synthetic cyberattack conditions
            if scenario == "gps_spoofing":
                gps_drift += rng.uniform(5.0, 15.0)

            elif scenario == "rf_jamming":
                snr = np.clip(
                    rng.normal(8.0, 3.0), 0, 60
                )
                packet_loss = np.clip(
                    rng.normal(0.40, 0.10), 0, 1
                )

            elif scenario == "network_flooding":
                packet_rate += rng.uniform(30.0, 80.0)

            records.append({
                "uav_id": "UAV_001",
                "sample_id": sample_id,
                "scenario": scenario,
                "gps_drift_m": round(gps_drift, 4),
                "snr_db": round(float(snr), 4),
                "packet_rate_hz": round(packet_rate, 4),
                "packet_loss_ratio": round(
                    float(packet_loss), 4
                ),
                "is_attack": int(scenario != "normal"),
            })

    return pd.DataFrame.from_records(records)


def main():
    project_root = Path(__file__).resolve().parents[2]
    output_dir = project_root / "results"
    output_dir.mkdir(parents=True, exist_ok=True)

    telemetry = generate_telemetry()

    output_file = output_dir / "synthetic_uav_telemetry.csv"
    telemetry.to_csv(output_file, index=False)

    print("UAV Cybersecurity Telemetry Simulation")
    print("=" * 45)
    print(f"Random seed: {RANDOM_SEED}")
    print(f"Total observations: {len(telemetry)}")

    print("\nScenario distribution:")
    print(telemetry["scenario"].value_counts().to_string())

    print("\nFirst five observations:")
    print(telemetry.head().to_string(index=False))

    print(f"\nDataset saved to: {output_file}")


if __name__ == "__main__":
    main()
