
import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from autoencoder import TelemetryAutoencoder


ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "results" / "models"

MODEL_PATH = MODEL_DIR / "autoencoder.pt"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"

FEATURES = [
    "gps_drift_m",
    "snr_db",
    "packet_rate_hz",
    "packet_loss_ratio",
]


class UAVAnomalyDetector:
    def __init__(self):
        # Load the trained PyTorch autoencoder.
        self.model = TelemetryAutoencoder(
            input_dim=len(FEATURES)
        )

        state_dict = torch.load(
            MODEL_PATH,
            map_location="cpu",
            weights_only=True,
        )

        self.model.load_state_dict(state_dict)
        self.model.eval()

        # Only load trusted, locally generated artifacts.
        self.scaler = joblib.load(SCALER_PATH)

        with METRICS_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:
            metrics = json.load(file)

        self.threshold = float(
            metrics["threshold"]
        )

        if (
            not math.isfinite(self.threshold)
            or self.threshold < 0
        ):
            raise ValueError(
                "Invalid saved anomaly threshold"
            )

        if hasattr(self.scaler, "feature_names_in_"):
            saved_features = list(
                self.scaler.feature_names_in_
            )

            if saved_features != FEATURES:
                raise ValueError(
                    "Scaler feature order does not match "
                    "the trained model configuration"
                )

        if self.scaler.n_features_in_ != len(FEATURES):
            raise ValueError(
                "Invalid scaler input dimension"
            )

    def predict(self, telemetry):
        # Preserve the original training feature order.
        values = []

        for feature in FEATURES:
            if feature not in telemetry:
                raise ValueError(
                    f"Missing telemetry feature: {feature}"
                )

            value = float(telemetry[feature])

            if not math.isfinite(value):
                raise ValueError(
                    f"Invalid value for {feature}"
                )

            values.append(value)

        input_df = pd.DataFrame(
            [values],
            columns=FEATURES,
        )

        # Reuse the exact fitted training scaler.
        scaled = self.scaler.transform(input_df)

        tensor = torch.tensor(
            scaled,
            dtype=torch.float32,
        )

        # Perform actual trained-model inference.
        with torch.no_grad():
            score = float(
                self.model.anomaly_score(tensor)
                .item()
            )

        is_anomaly = score > self.threshold

        return {
            "anomaly_score": score,
            "threshold": self.threshold,
            "is_anomaly": bool(is_anomaly),
            "detection_result": (
                "ANOMALY"
                if is_anomaly
                else "NORMAL"
            ),
        }


def generate_alert(
    detector,
    telemetry,
    uav_id="UAV_001",
):
    prediction = detector.predict(telemetry)

    if not prediction["is_anomaly"]:
        return None, prediction

    alert = {
        "uav_id": uav_id,
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": prediction["anomaly_score"],
        "threshold": prediction["threshold"],
        "detection_result": "ANOMALY",
        "source": "pytorch_autoencoder",
        "data_source": "synthetic_uav_telemetry",
        "detected_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "telemetry": {
            feature: float(telemetry[feature])
            for feature in FEATURES
        },
    }

    return alert, prediction


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default=str(
            ROOT / "results" / "ai_test_predictions.csv"
        ),
    )

    parser.add_argument(
        "--row-index",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--first-detected",
        action="store_true",
        help=(
            "Select the first observation previously "
            "flagged as anomalous in the saved test CSV"
        ),
    )

    parser.add_argument(
        "--output",
        default=str(
            ROOT / "results" / "alerts"
            / "ai_detected_alert.json"
        ),
    )

    parser.add_argument(
        "--uav-id",
        default="UAV_001",
    )

    args = parser.parse_args()

    if args.first_detected and args.row_index is not None:
        parser.error(
            "Select either --first-detected "
            "or --row-index"
        )

    detector = UAVAnomalyDetector()

    df = pd.read_csv(args.input)

    for feature in FEATURES:
        if feature not in df.columns:
            raise ValueError(
                f"Missing CSV feature: {feature}"
            )

    if args.first_detected:
        if "predicted_attack" not in df.columns:
            raise ValueError(
                "CSV has no predicted_attack column"
            )

        matching = df.index[
            df["predicted_attack"] == 1
        ]

        if len(matching) == 0:
            raise ValueError(
                "No previously detected anomalies found"
            )

        selected_index = int(matching[0])

    elif args.row_index is not None:
        selected_index = args.row_index

    else:
        selected_index = 0

    if not 0 <= selected_index < len(df):
        raise ValueError(
            "Selected row index is out of range"
        )

    row = df.iloc[selected_index]

    telemetry = {
        feature: float(row[feature])
        for feature in FEATURES
    }

    print("=" * 60)
    print("UAV AI ANOMALY INFERENCE")
    print("=" * 60)

    print(f"Input observation: {selected_index}")

    for feature, value in telemetry.items():
        print(f"{feature}: {value}")

    alert, prediction = generate_alert(
        detector,
        telemetry,
        uav_id=args.uav_id,
    )

    print(
        f"\nReconstruction error: "
        f"{prediction['anomaly_score']:.8f}"
    )

    print(
        f"Anomaly threshold: "
        f"{prediction['threshold']:.8f}"
    )

    print(
        f"Detection result: "
        f"{prediction['detection_result']}"
    )

    if alert is None:
        print(
            "\nNormal telemetry. "
            "No security alert generated."
        )
        return

    output = Path(args.output)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            alert,
            file,
            indent=4,
            allow_nan=False,
        )

    print("\nSECURITY ALERT GENERATED")
    print(f"Output: {output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
