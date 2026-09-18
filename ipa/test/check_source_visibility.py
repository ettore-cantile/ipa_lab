#!/usr/bin/env python3
"""
check_source_visibility.py -- le funzioni C sono visibili dove vengono usate?

--------------------------------------------------------------------------
PERCHE' ESISTE
--------------------------------------------------------------------------
I sorgenti eBPF di questo progetto non sono file: sono STRINGHE Python
concatenate in combinazioni diverse a seconda del chiamante, e ritagliate dal
preprocessore con macro diverse. `setup_template` compila
`"#define IPA_ARCH_COMBINED 1" + DISPATCHER + LEAF`; altri percorsi compilano
il leaf da solo; `count_lookups` aggiunge `IPA_COUNT_LOOKUPS`.

Una funzione puo' quindi stare PRIMA del suo uso nel file e sparire lo stesso
nella combinazione che conta. E' successo il 2026-09-18: `ipa_div_trunc` era
definita dentro `#ifndef IPA_ARCH_COMBINED`, cioe' esattamente il blocco che
`setup_template` disattiva, e la compilazione moriva con

    error: call to undeclared function 'ipa_div_trunc'

Un controllo testuale ("la definizione viene prima dell'uso?") diceva che era
tutto a posto. Serviva guardare il sorgente COME LO VEDE IL COMPILATORE.

--------------------------------------------------------------------------
CHE COSA FA, E CHE COSA NON FA
--------------------------------------------------------------------------
Valuta `#ifdef` / `#ifndef` / `#else` / `#endif` con un insieme di macro dato,
tiene le righe attive, e verifica che ogni funzione sorvegliata sia definita
prima del primo uso. Gli `#if` con espressioni vere e proprie li considera
attivi: e' un'approssimazione voluta, perche' qui servono solo le guardie per
nome.

NON e' un compilatore e non sostituisce una compilazione vera: dice se una
funzione e' VISIBILE, non se il corpo e' corretto. Gira pero' ovunque, senza
root e senza BCC, che e' il motivo per cui e' utile prima di spedire.

    python3 ipa/test/check_source_visibility.py
"""
import os
import re
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, GREY, NC = "\033[0;32m", "\033[0;31m", "\033[0;90m", "\033[0m"

# Le funzioni da sorvegliare: (nome, come si riconosce la definizione).
SORVEGLIATE = [("ipa_div_trunc", "static __always_inline long long ipa_div_trunc")]


def preprocessa(src: str, definite: set) -> str:
    """Le sole righe che sopravvivono alle guardie, date le macro definite."""
    fuori, stack = [], []
    for riga in src.splitlines():
        t = riga.strip()
        m = re.match(r"#\s*(ifndef|ifdef)\s+(\w+)", t)
        if m:
            stack.append((m.group(2) in definite) if m.group(1) == "ifdef"
                         else (m.group(2) not in definite))
            continue
        if re.match(r"#\s*if\b", t):
            stack.append(True)
            continue
        if re.match(r"#\s*else\b", t):
            if stack:
                stack[-1] = not stack[-1]
            continue
        if re.match(r"#\s*endif\b", t):
            if stack:
                stack.pop()
            continue
        if all(stack):
            fuori.append(riga)
    return "\n".join(fuori)


def controlla(nome_caso: str, src: str, definite: set) -> bool:
    vivo = preprocessa(src, definite)
    macro = ", ".join(sorted(definite)) or "nessuna macro"
    esito = True
    for fn, firma in SORVEGLIATE:
        uso = re.search(re.escape(fn) + r"\s*\(", vivo)
        deff = vivo.find(firma)
        if uso is None:
            continue
        if deff < 0:
            print(f"  {RED}[FAIL]{NC} {nome_caso} [{macro}]: `{fn}` usata ma "
                  f"NON definita -- non compila")
            esito = False
        elif deff > uso.start():
            print(f"  {RED}[FAIL]{NC} {nome_caso} [{macro}]: `{fn}` definita "
                  f"DOPO il primo uso -- non compila")
            esito = False
        else:
            print(f"  {GREEN}[PASS]{NC} {nome_caso} {GREY}[{macro}]{NC}: "
                  f"`{fn}` visibile all'uso")
    return esito


def main():
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER as D,
                                    EBPF_ARCH_GENERIC_2LAYER as L)
    from ebpf_modular import EBPF_MODULAR_FULL as M

    p2 = "#define IPA_ARCH_COMBINED 1\n" + D + "\n" + L
    casi = [
        # Le combinazioni che i chiamanti costruiscono davvero.
        ("P2 combinato (setup_template)", p2, {"IPA_ARCH_COMBINED"}),
        ("P2 combinato + count_lookups", p2,
         {"IPA_ARCH_COMBINED", "IPA_COUNT_LOOKUPS"}),
        ("P2 leaf da solo", L, set()),
        ("P3 completo", M, set()),
        ("P3 + count_lookups", M, {"IPA_COUNT_LOOKUPS"}),
    ]
    print("=== visibilita' delle funzioni C nelle combinazioni compilate ===")
    esiti = [controlla(n, s, d) for n, s, d in casi]
    print()
    if all(esiti):
        print(f"{GREEN}tutte le combinazioni compilabili{NC}")
        return 0
    print(f"{RED}almeno una combinazione non compila{NC}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
