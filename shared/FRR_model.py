import torch
import torch.nn as nn
import torch.nn.functional as F


class FastRerouteMLP(nn.Module):
    """Method 1 - standard float weights.
    Quantization happens AFTER training (post-training quantization)
    through extract_weights.py with SCALE_FACTOR=128.
    """

    def __init__(self, n_interfaces=6, n_nodes=22, hidden_dim=32):
        super(FastRerouteMLP, self).__init__()
        self.n_interfaces = n_interfaces
        self.n_classes = n_interfaces + 1  # +1 for DROP class

        input_dim = (
            n_interfaces       # output interface states
            + n_interfaces     # ingress interface (one-hot)
            + 1                # normalized TTL
            + n_nodes          # current node (one-hot)
        )
        print("DIM INPUT: " + str(input_dim))

        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.out = nn.Linear(hidden_dim, self.n_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.out(x)  # raw output (logits)


class QATFastRerouteMLP(FastRerouteMLP):
    """Method 2 - Quantization-Aware Training (QAT).

    Same architecture as FastRerouteMLP, but during the forward pass weights
    are fake-quantized: scaled to int8, rounded, then rescaled back to float.
    This lets the gradient account for quantization error during training
    (Straight-Through Estimator, STE).

    The result is a model whose float weights are already optimized to survive
    the int8 clamp: extract_weights.py does not change, but the produced
    weights have less overflow and less rounding error than Method 1.
    """

    SCALE = 128.0  # must match SCALE_FACTOR in extract_weights.py

    @staticmethod
    def _fake_quant(w: torch.Tensor) -> torch.Tensor:
        """Simulate int8 quantization with SCALE=128.

        w_q = clamp(round(w * 128), -128, 127) / 128

        The clamp is differentiable through STE: the gradient passes through
        round() and clamp() as if they were the identity, so training converges
        normally.
        """
        w_scaled  = w * QATFastRerouteMLP.SCALE
        w_rounded = torch.round(w_scaled)
        w_clamped = torch.clamp(w_rounded, -128, 127)
        return w_clamped / QATFastRerouteMLP.SCALE

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # fc1
        x = F.relu(F.linear(x,
                             self._fake_quant(self.fc1.weight),
                             self.fc1.bias))
        # fc2
        x = F.relu(F.linear(x,
                             self._fake_quant(self.fc2.weight),
                             self.fc2.bias))
        # output layer
        x = F.linear(x,
                      self._fake_quant(self.out.weight),
                      self.out.bias)
        return x
