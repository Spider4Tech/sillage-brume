# -*- coding: utf-8 -*-
"""SILLAGE — suite cryptographique expérimentale par décodage bruité.

Version 0.3.0 : KEM (LPN creux QC, transformée FO), BRUME-512 (permutation
S-box 4 bits + diffusion par graphe de Cayley pondéré, AEAD duplex, mode TE,
hachage) et SIG (MPC-in-the-Head sur le décodage de syndrome). Banc de tests et de
cryptanalyse : ../tests (python3 -m tests.run_all).

AVERTISSEMENT : prototype de recherche. Ne pas utiliser en production.
"""

__version__ = "0.4.0"

from .sillage_kem import PARAMS as KEM_PARAMS
from .brume512 import BRUME512_PROFILES, BRUME512P_PROFILES, Brume512TagError, Brume512TamperError
from .sillage_sig import SIG_PARAMS
from .rapide import SillageKEM, SillageSIG, Brume512, Brume512P, brume512_hash, brume512_hash_arbre

__all__ = ["SillageKEM", "KEM_PARAMS",
           "Brume512", "BRUME512_PROFILES", "Brume512P", "BRUME512P_PROFILES", "brume512_hash", "brume512_hash_arbre",
           "Brume512TagError", "Brume512TamperError",
           "SillageSIG", "SIG_PARAMS"]
