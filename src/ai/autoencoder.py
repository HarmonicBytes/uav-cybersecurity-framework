
import torch
from torch import nn


class TelemetryAutoencoder(nn.Module):
    """
    Lightweight neural network for UAV telemetry anomaly detection.

    Input features:
      1. GPS drift
      2. Signal-to-noise ratio
      3. Packet transmission rate
      4. Packet loss ratio
    """

    def __init__(self, input_dim=4):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 3),
        )

        self.decoder = nn.Sequential(
            nn.Linear(3, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        reconstructed = self.decoder(encoded)
        return reconstructed

    def anomaly_score(self, x):
        reconstructed = self.forward(x)
        return torch.mean(
            (x - reconstructed) ** 2,
            dim=1,
        )


if __name__ == "__main__":
    model = TelemetryAutoencoder()
    model.eval()

    # Test the network using five synthetic observations
    sample_input = torch.rand(5, 4)

    with torch.no_grad():
        reconstructed = model(sample_input)
        scores = model.anomaly_score(sample_input)

    print("UAV Telemetry Autoencoder")
    print("=" * 35)
    print(model)
    print(f"\nInput shape: {sample_input.shape}")
    print(f"Output shape: {reconstructed.shape}")
    print(f"Anomaly scores: {scores}")
    print(
        "Trainable parameters:",
        sum(p.numel() for p in model.parameters()),
    )
