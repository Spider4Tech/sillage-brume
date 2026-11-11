# -*- coding: utf-8 -*-
"""SILLAGE — suite cryptographique expérimentale par décodage bruité.

Version 0.5.0 : KEM (LPN creux QC, transformée FO), BRUME-512 (permutation
S-box 4 bits + diffusion par graphe de Cayley pondéré, AEAD duplex, mode TE,
hachage ; S-box AD412650BFEC7893 depuis la v0.5) et SIG. La signature de la v0.5
est SillageVOLE (VOLE-in-the-Head sur SD régulier, C seulement) ; SillageSIG
(MPC-in-the-Head, v0.4) est conservée comme référence. Banc de tests et de
cryptanalyse : ../tests (python3 -m tests.run_all).

AVERTISSEMENT : prototype de recherche. Ne pas utiliser en production.
"""

__version__ = "0.5.0"

from .sillage_kem import PARAMS as KEM_PARAMS
from .brume512 import BRUME512_PROFILES, BRUME512P_PROFILES, Brume512TagError, Brume512TamperError
from .sillage_sig import SIG_PARAMS
from .rapide import SillageKEM, SillageSIG, SillageVOLE, Brume512, Brume512P, brume512_hash, brume512_hash_arbre

__all__ = ["SillageKEM", "KEM_PARAMS",
           "Brume512", "BRUME512_PROFILES", "Brume512P", "BRUME512P_PROFILES", "brume512_hash", "brume512_hash_arbre",
           "Brume512TagError", "Brume512TamperError",
           "SillageSIG", "SIG_PARAMS", "SillageVOLE"]
