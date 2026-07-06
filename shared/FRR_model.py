import torch
import torch.nn as nn
import torch.nn.functional as F


class FastRerouteMLP(nn.Module):
    """Metodo 1 — pesi float standard.
    La quantizzazione avviene DOPO il training (post-training quantization)
    tramite extract_weights.py con SCALE_FACTOR=128.
    """

    def __init__(self, n_interfaces=6, n_nodes=22, hidden_dim=32):
        super(FastRerouteMLP, self).__init__()
        self.n_interfaces = n_interfaces
        self.n_classes = n_interfaces + 1  # +1 for DROP class

        input_dim = (
            n_interfaces       # stato delle interfacce di uscita
            + n_interfaces     # interfaccia di ingresso (one-hot)
            + 1                # TTL normalizzato
            + n_nodes          # nodo corrente (one-hot)
        )
        print("DIM INPUT: " + str(input_dim))

        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.out = nn.Linear(hidden_dim, self.n_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.out(x)  # output grezzo (logits)


class QATFastRerouteMLP(FastRerouteMLP):
    """Metodo 2 — Quantization-Aware Training (QAT).

    Stessa architettura di FastRerouteMLP, ma durante il forward pass i pesi
    vengono 'fake-quantizzati': scalati a int8, arrotondati, poi ri-scalati a
    float. In questo modo il gradiente durante il training tiene conto
    dell'errore di quantizzazione (Straight-Through Estimator, STE).

    Il risultato e' un modello i cui pesi float sono gia' ottimizzati per
    sopravvivere al clamp int8: extract_weights.py non cambia, ma i pesi
    prodotti avranno meno overflow e meno errore di arrotondamento rispetto
    al Metodo 1.
    """

    SCALE = 128.0  # deve coincidere con SCALE_FACTOR in extract_weights.py

    @staticmethod
    def _fake_quant(w: torch.Tensor) -> torch.Tensor:
        """Simula la quantizzazione int8 con SCALE=128.

        w_q = clamp(round(w * 128), -128, 127) / 128

        Il clamp e' differenziabile via STE: il gradiente passa attraverso
        round() e clamp() come se fossero l'identita', quindi il training
        converge normalmente.
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
