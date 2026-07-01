#!/usr/bin/env python3
import argparse
import time
import random
from scapy.all import send, IP, UDP, Packet
from scapy.fields import ByteField, ShortField

class IPA_HDR(Packet):
    name = "IPAHeader"
    fields_desc = [
        ByteField("model_id",          42),
        ByteField("type_and_param_sz",  0),
        ShortField("scaling",          100),
        ByteField("input_size",          4),
        ByteField("output_size",         1),
        ByteField("hidden_layers",       4),
        ByteField("neurons_per_layer",   2),
    ]

parser = argparse.ArgumentParser(description="IPA switch performance tester")
parser.add_argument("--count", type=int, default=10, help="Numero di pacchetti da inviare")
parser.add_argument("--delay", type=float, default=0.0, help="Ritardo tra i pacchetti in sec")
parser.add_argument("--dest", type=str, default="frankfurt", help="IP o Hostname di destinazione")
args = parser.parse_args()

N = args.count
DELAY = args.delay
DEST = args.dest
MODEL = 42

print(f"\n[1/1] Invio di {N} pacchetti IPA a '{DEST}' (model_id={MODEL}) con TTL dinamico...")

t_start = time.perf_counter()
for i in range(N):
    # Generiamo un TTL casuale per stressare l'arrotondamento in Kernel Space
    random_ttl = random.randint(30, 64)
    
    packet = IP(dst=DEST, ttl=random_ttl) / UDP(dport=9999) / IPA_HDR(
        model_id=MODEL,
        input_size=4,
        neurons_per_layer=2,
        hidden_layers=4
    )
    send(packet, verbose=False)
    if DELAY > 0:
        time.sleep(DELAY)
        
t_end = time.perf_counter()
elapsed = t_end - t_start
throughput = N / elapsed

print(f"\nRiepilogo risultati:")
print(f"  Pacchetti inviati    : {N}")
print(f"  Tempo totale         : {elapsed:.3f} s")
print(f"  Throughput (send)    : {throughput:.1f} pkt/s")
print("\n[!] Ora controlla i log di trace_pipe su Frankfurt per contare i REDIRECT e i TABLE MISS.")