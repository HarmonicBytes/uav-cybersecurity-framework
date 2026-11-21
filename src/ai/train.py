
import json
import random
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn

from autoencoder import TelemetryAutoencoder


# ============================================================
# CONFIGURATION
# ============================================================

SEED = 42
EPOCHS = 100
BATCH_SIZE = 64
LEARNING_RATE = 0.001

FEATURES = [
    "gps_drift_m",
    "snr_db",
    "packet_rate_hz",
    "packet_loss_ratio",
]

ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = ROOT / "results" / "synthetic_uav_telemetry.csv"
MODEL_DIR = ROOT / "results" / "models"
FIGURES_DIR = ROOT / "figures"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

# Reproducible CPU execution for this experiment
torch.set_num_threads(1)
torch.use_deterministic_algorithms(True)


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 55)
print("UAV CYBERSECURITY - AUTOENCODER TRAINING")
print("=" * 55)

df = pd.read_csv(DATA_PATH)

normal_df = df[df["is_attack"] == 0].copy()
attack_df = df[df["is_attack"] == 1].copy()

# Training uses normal telemetry only.
# 60% training, 20% validation, 20% testing.
normal_train, normal_remaining = train_test_split(
    normal_df,
    test_size=0.4,
    random_state=SEED,
    shuffle=True,
)

normal_val, normal_test = train_test_split(
    normal_remaining,
    test_size=0.5,
    random_state=SEED,
    shuffle=True,
)

# Attack observations are reserved for evaluation.
# Use 20% per attack scenario as the test set.
_, attack_test = train_test_split(
    attack_df,
    test_size=0.2,
    random_state=SEED,
    stratify=attack_df["scenario"],
)

test_df = pd.concat(
    [normal_test, attack_test],
    ignore_index=True,
)

test_df = test_df.sample(
    frac=1,
    random_state=SEED,
).reset_index(drop=True)

print(f"Training samples: {len(normal_train)}")
print(f"Validation samples: {len(normal_val)}")
print(f"Test samples: {len(test_df)}")


# ============================================================
# FEATURE NORMALIZATION
# ============================================================

scaler = StandardScaler()

X_train = scaler.fit_transform(normal_train[FEATURES])
X_val = scaler.transform(normal_val[FEATURES])
X_test = scaler.transform(test_df[FEATURES])

train_tensor = torch.tensor(
    X_train, dtype=torch.float32
)
val_tensor = torch.tensor(
    X_val, dtype=torch.float32
)
test_tensor = torch.tensor(
    X_test, dtype=torch.float32
)

train_loader = torch.utils.data.DataLoader(
    torch.utils.data.TensorDataset(train_tensor),
    batch_size=BATCH_SIZE,
    shuffle=True,
    generator=torch.Generator().manual_seed(SEED),
)


# ============================================================
# INITIALIZE AUTOENCODER
# ============================================================

model = TelemetryAutoencoder(input_dim=4)

criterion = nn.MSELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE,
)

train_losses = []
val_losses = []


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nStarting AI model training...\n")

for epoch in range(EPOCHS):

    model.train()
    epoch_loss = 0.0

    for (batch,) in train_loader:

        optimizer.zero_grad()

        reconstructed = model(batch)
        loss = criterion(reconstructed, batch)

        loss.backward()
        optimizer.step()

        epoch_loss += loss.item() * len(batch)

    average_train_loss = epoch_loss / len(train_tensor)

    model.eval()

    with torch.no_grad():
        val_output = model(val_tensor)
        val_loss = criterion(
            val_output, val_tensor
        ).item()

    train_losses.append(average_train_loss)
    val_losses.append(val_loss)

    if (epoch + 1) % 10 == 0:
        print(
            f"Epoch {epoch + 1:3d}/{EPOCHS} | "
            f"Train Loss: {average_train_loss:.6f} | "
            f"Val Loss: {val_loss:.6f}"
        )


# ============================================================
# ANOMALY THRESHOLD
# ============================================================

model.eval()

with torch.no_grad():
    validation_scores = (
        model.anomaly_score(val_tensor)
        .cpu()
        .numpy()
    )

    test_scores = (
        model.anomaly_score(test_tensor)
        .cpu()
        .numpy()
    )

# Threshold selected using normal validation data only.
threshold = float(
    np.quantile(validation_scores, 0.99)
)

predictions = (test_scores > threshold).astype(int)

actual = test_df["is_attack"].to_numpy()


# ============================================================
# EVALUATE MODEL
# ============================================================

metrics = {
    "accuracy": float(
        accuracy_score(actual, predictions)
    ),
    "precision": float(
        precision_score(
            actual, predictions, zero_division=0
        )
    ),
    "recall": float(
        recall_score(
            actual, predictions, zero_division=0
        )
    ),
    "f1_score": float(
        f1_score(
            actual, predictions, zero_division=0
        )
    ),
    "threshold": threshold,
    "seed": SEED,
    "epochs": EPOCHS,
}

tn, fp, fn, tp = confusion_matrix(
    actual, predictions, labels=[0, 1]
).ravel()

metrics["true_negative"] = int(tn)
metrics["false_positive"] = int(fp)
metrics["false_negative"] = int(fn)
metrics["true_positive"] = int(tp)

print("\n" + "=" * 55)
print("AI ANOMALY DETECTION RESULTS")
print("=" * 55)

for name in ["accuracy", "precision", "recall", "f1_score"]:
    print(f"{name}: {metrics[name]:.4f}")

print(f"Anomaly threshold: {threshold:.6f}")
print(f"True positives: {tp}")
print(f"True negatives: {tn}")
print(f"False positives: {fp}")
print(f"False negatives: {fn}")

test_df["anomaly_score"] = test_scores
test_df["predicted_attack"] = predictions

print("\nDetection rate per scenario:")

for scenario, group in test_df.groupby("scenario"):
    if scenario == "normal":
        rate = (group["predicted_attack"] == 1).mean()
        print(f"{scenario}: false positive rate = {rate:.2%}")
    else:
        rate = (group["predicted_attack"] == 1).mean()
        print(f"{scenario}: detection rate = {rate:.2%}")


# ============================================================
# SAVE TRAINED MODEL AND RESULTS
# ============================================================

torch.save(
    model.state_dict(),
    MODEL_DIR / "autoencoder.pt",
)

joblib.dump(
    scaler,
    MODEL_DIR / "scaler.joblib",
)

with open(
    MODEL_DIR / "metrics.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(metrics, file, indent=4)

test_df.to_csv(
    ROOT / "results" / "ai_test_predictions.csv",
    index=False,
)

# Training curve for research analysis
plt.figure(figsize=(8, 5))

plt.plot(train_losses, label="Training Loss")
plt.plot(val_losses, label="Validation Loss")

plt.xlabel("Epoch")
plt.ylabel("Mean Squared Error")
plt.title("UAV Autoencoder Training Performance")
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()

plt.savefig(
    FIGURES_DIR / "autoencoder_training.png",
    dpi=300,
)

print("\nModel and metrics saved successfully.")
print("Training figure saved successfully.")

plt.show()
