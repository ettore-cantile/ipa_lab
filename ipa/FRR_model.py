"""FRR_model.py -- the PyTorch model of the trained checkpoint (fast-reroute MLP).

Used only to read the checkpoint and extract its weights (extract_weights.py).
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class FastRerouteMLP(nn.Module):
    """Method 1 - standard float weights."""

    def __init__(self, n_interfaces=6, n_nodes=22, hidden_dim=32,
                 n_classes=7):
        """`n_classes` is the model's OUTPUT WIDTH and nothing more."""
        super(FastRerouteMLP, self).__init__()
        self.n_interfaces = n_interfaces
        self.n_classes = int(n_classes)

        input_dim = (
            n_interfaces
            + n_interfaces
            + 1
            + n_nodes
        )
        print("DIM INPUT: " + str(input_dim))

        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.out = nn.Linear(hidden_dim, self.n_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.out(x)


class QATFastRerouteMLP(FastRerouteMLP):
    """Method 2 - Quantization-Aware Training (QAT)."""

    SCALE = 128.0

    @staticmethod
    def _fake_quant(w: torch.Tensor) -> torch.Tensor:
        """Simulate int8 quantization with SCALE=128."""
        w_scaled  = w * QATFastRerouteMLP.SCALE
        w_rounded = torch.round(w_scaled)
        w_clamped = torch.clamp(w_rounded, -128, 127)
        return w_clamped / QATFastRerouteMLP.SCALE

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = F.relu(F.linear(x,
                             self._fake_quant(self.fc1.weight),
                             self.fc1.bias))
        x = F.relu(F.linear(x,
                             self._fake_quant(self.fc2.weight),
                             self.fc2.bias))
        x = F.linear(x,
                      self._fake_quant(self.out.weight),
                      self.out.bias)
        return x
