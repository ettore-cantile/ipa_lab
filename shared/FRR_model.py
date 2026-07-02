import torch
import torch.nn as nn
import torch.nn.functional as F

class FastRerouteMLP(nn.Module):
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
        return self.out(x)  # output grezzo (logits)
