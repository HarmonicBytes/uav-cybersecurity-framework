
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "results" / "synthetic_uav_telemetry.csv"
FIGURES_DIR = PROJECT_ROOT / "figures"

FIGURES_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(DATASET)

features = {
    "gps_drift_m": "GPS Drift (m)",
    "snr_db": "Signal-to-Noise Ratio (dB)",
    "packet_rate_hz": "Packet Rate (Hz)",
    "packet_loss_ratio": "Packet Loss Ratio",
}

scenarios = [
    "normal",
    "gps_spoofing",
    "rf_jamming",
    "network_flooding",
]

fig, axes = plt.subplots(2, 2, figsize=(12, 8))

for ax, (column, label) in zip(axes.flat, features.items()):
    for scenario in scenarios:
        values = df.loc[df["scenario"] == scenario, column]
        ax.hist(
            values,
            bins=30,
            alpha=0.45,
            density=True,
            label=scenario.replace("_", " "),
        )

    ax.set_title(label)
    ax.set_xlabel(label)
    ax.set_ylabel("Probability Density")
    ax.grid(alpha=0.2)

handles, labels = axes.flat[0].get_legend_handles_labels()

fig.legend(
    handles,
    labels,
    loc="lower center",
    ncol=4,
    frameon=False,
)

fig.suptitle("Synthetic UAV Telemetry Under Cyberattack Scenarios")
fig.tight_layout(rect=[0, 0.07, 1, 0.95])

output_file = FIGURES_DIR / "telemetry_distributions.png"

fig.savefig(output_file, dpi=300, bbox_inches="tight")

print("Visualization generated successfully!")
print(f"Figure saved to: {output_file}")

plt.show()
