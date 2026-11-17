# -*- coding: utf-8 -*-
"""
SILLAGE — démonstrateur de bout en bout
========================================
Scénario complet : établissement de clé post-quantique, canal chiffré
auto-correcteur, signature d'un ordre de mission — puis simulation des
attaques de base (altération, rejeu, falsification) et des réponses du
système.

Usage : python3 demo.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sillage.sillage_kem import SillageKEM
from sillage.rapide import Brume1024, Brume1024TagError, Brume1024TamperError
from sillage.sillage_sig import SillageSIG

SEP = "─" * 74


def step(title):
    print()
    print(SEP)
    print(f"  {title}")
    print(SEP)


def main():
    t_all = time.perf_counter()
    print("╔" + "═" * 72 + "╗")
    print("║  SILLAGE — démonstrateur de la suite cryptographique            ║")
    print("║  KEM par décodage bruité · BRUME-1024q (c = 384, 32 tours) ·    ║")
    print("║  signatures par décodage de syndrome                            ║")
    print("╚" + "═" * 72 + "╝")

    # ------------------------------------------------------------------
    step("1. Établissement de clé — Sillage-KEM (Alice ⇄ Bob)")
    kem = SillageKEM("Sillage-128")
    t0 = time.perf_counter()
    pk_alice, sk_alice = kem.keygen()
    t_kg = time.perf_counter() - t0
    print(f"  Alice génère sa paire de clés            ({t_kg*1e3:6.1f} ms)")
    print(f"    clé publique  : {kem.sizes()['pk_bytes']:,} octets | "
          f"chiffré KEM : {kem.sizes()['ct_bytes']:,} octets")
    print(f"    hypothèse     : récupérer (x, y) creux depuis s = x·h ⊕ y")

    t0 = time.perf_counter()
    ct_bob, ss_bob = kem.encaps(pk_alice)
    t_enc = time.perf_counter() - t0
    print(f"  Bob encapsule une clé de session         ({t_enc*1e3:6.1f} ms)")

    t0 = time.perf_counter()
    ss_alice = kem.decaps(sk_alice, ct_bob)
    t_dec = time.perf_counter() - t0
    print(f"  Alice décapsule                          ({t_dec*1e3:6.1f} ms)")
    print(f"  clé partagée identique : {ss_alice == ss_bob}")
    print(f"  clé (16 premiers octets) : {ss_alice[:16].hex()}")

    # Attaque : altération du chiffré KEM → rejet implicite
    ct_attaque = (ct_bob[0], ct_bob[1] ^ (1 << 1234))
    ss_eve = kem.decaps(sk_alice, ct_attaque)
    print(f"  [attaque] chiffré altéré → rejet implicite : {ss_eve != ss_alice} "
          f"(Eve obtient une clé inutilisable, sans le savoir)")

    # ------------------------------------------------------------------
    step("2. Canal chiffré — BRUME-1024q (clé dérivée du KEM)")
    from sillage.sillage_common import shake
    brume = Brume1024("BRUME-1024q",
                      key=shake(ss_alice, 64, b"SILLAGE|brume-key"))  # KDF 512 bits
    nonce = os.urandom(24)
    mission = ("ORDRE 2026-114 — Rendez-vous au point VAUTOUR à 04h00, "
               "emporter le matériel gamma, brûler après lecture.").encode("utf-8")
    ct, tag = brume.encrypt(nonce, mission)
    print(f"  message clair   : {mission[:48].decode()}…")
    print(f"  chiffré (32 o)  : {ct[:32].hex()}")
    pt = brume.decrypt(nonce, ct, tag)
    print(f"  déchiffrement   : {'OK' if pt == mission else 'ÉCHEC'} | "
          f"tag 256 bits vérifié")

    # Attaque : altération du tag
    try:
        brume.decrypt(nonce, ct, bytes(len(tag)), )
        print("  [attaque] tag falsifié  → ACCEPTÉ (bug !)")
    except Brume1024TagError:
        print("  [attaque] tag falsifié  → rejeté (Brume1024TagError)")

    # Attaque : extension du chiffré (bloc nul absorbé)
    try:
        brume.decrypt(nonce, ct + b"\x00" * 32, tag)
        print("  [attaque] ct étendu     → ACCEPTÉ (bug !)")
    except Brume1024TagError:
        print("  [attaque] ct étendu     → rejeté (le bourrage 0x01 et le domaine délimitent le texte)")

    # ------------------------------------------------------------------
    step("3. Mode auto-correcteur (TE) — canal bruité, altération, réparation")
    ct_te, pars, tag_te, meta = brume.encrypt_te(nonce, mission)
    print(f"  parités TE      : {len(pars)} octets "
          f"({len(pars)/len(ct_te)*100:.1f} % de surcoût)")

    canal = bytearray(ct_te)
    canal[40] ^= 0xFF          # 1 octet foudroyé (masque quelconque)
    canal[90] ^= 0x5A          # un autre, dans un autre bloc
    pt2, corrections = brume.decrypt_te(nonce, bytes(canal), pars, tag_te, meta)
    print(f"  canal bruité    : 2 octets altérés → corrigés aux positions {corrections}")
    print(f"  plaintext       : {'INTACT' if pt2 == mission else 'PERDU'}")

    canal2 = bytearray(ct_te)
    canal2[40] ^= 0xFF
    canal2[45] ^= 0x01         # 2 erreurs dans le MÊME bloc → échec bruyant
    try:
        brume.decrypt_te(nonce, bytes(canal2), pars, tag_te, meta)
        print("  2 erreurs/bloc  : non détectées (bug)")
    except (Brume1024TamperError, Brume1024TagError) as e:
        print(f"  2 erreurs/bloc  : ÉCHEC BRUYANT ({type(e).__name__}) — "
              "tamper-evidence native")

    # ------------------------------------------------------------------
    step("4. Signatures — Sillage-SIG (MPC-in-the-Head, décodage de syndrome)")
    sig = SillageSIG("Sillage-SIG-128")
    pk_sig, sk_sig = sig.keygen()
    print(f"  clé publique : {sig.sizes()['pk_bytes']} octets | "
          f"signature : {sig.sizes()['sig_bytes']:,} octets")
    t0 = time.perf_counter()
    signature = sig.sign(sk_sig, pk_sig, mission)
    t_s = time.perf_counter() - t0
    ok = sig.verify(pk_sig, mission, signature)
    print(f"  signature de l'ordre de mission         ({t_s*1e3:6.1f} ms) → "
          f"vérification : {ok}")

    faux = mission.replace(b"VAUTOUR", b"VAUTOUR-BIS")
    print(f"  [attaque] message falsifié → vérification : "
          f"{sig.verify(pk_sig, faux, signature)}")
    print(f"  [attaque] signature tronquée → {sig.verify(pk_sig, mission, signature[:-100])}")

    # ------------------------------------------------------------------
    step("5. Résumé")
    print(f"  durée totale du scénario : {time.perf_counter()-t_all:.2f} s")
    print("""
  Propriétés illustrées
    · établissement de clé par décodage de syndrome quasi-cyclique (LPN
      creux, transformée FO à rejet implicite) ;
    · confidentialité + intégrité du canal (BRUME-1024q : duplex à clé dans
      tout l'état, c = 384 pour 128 bits quantiques, S-box 4 bits optimale,
      graphe de Cayley pondéré de D256 ; C3 ≥ 21 et C4 ≥ 28 certifiés →
      ≥ 224 S-box actives sur 32 tours — batterie : python3 -m tests.run_all) ;
    · réparation des erreurs canal accidentelles (mode TE) ; l'intégrité
      face à un adversaire reste assurée par le tag ;
    · non-répudiation par décodage de syndrome (45 ans de cryptanalyse,
      aucun algorithme quantique connu au-delà d'ISD quantique).

  Rappel : prototype de RECHERCHE — paramètres préliminaires, non soumis
  à cryptanalyse tierce. Ne pas déployer en production.""")


if __name__ == "__main__":
    main()
