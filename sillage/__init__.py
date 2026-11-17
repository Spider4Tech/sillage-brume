# -*- coding: utf-8 -*-
"""SILLAGE — suite cryptographique expérimentale par décodage bruité.

Version 0.6.0 : KEM (LPN creux QC, transformée FO), BRUME-1024q (permutation de
1 024 bits, S-box 4 bits + diffusion par graphe de Cayley pondéré de D256, éponge à
c = 384 pour 128 bits quantiques : hachage, XOF, AEAD duplex, AEAD parallèle, mode
TE ; C seulement) et SIG. BRUME-1024q remplace BRUME-512 (v0.5, archivée dans
tests/historique_v05/). La signature est SillageVOLE (VOLE-in-the-Head sur SD
régulier, C seulement) ; SillageSIG (MPC-in-the-Head, v0.4) est conservée comme
référence. Banc de tests et de cryptanalyse : ../tests (python3 -m tests.run_all).

AVERTISSEMENT : prototype de recherche. Ne pas utiliser en production.
"""

__version__ = "0.6.0"

from .sillage_kem import PARAMS as KEM_PARAMS
from .sillage_sig import SIG_PARAMS
from .rapide import (SillageKEM, SillageSIG, SillageVOLE, Brume1024, Brume1024P, BRUME1024_PROFILES,
                     BRUME1024P_PROFILES, Brume1024TagError, Brume1024TamperError, brume1024_hash, brume1024_xof)

__all__ = ["SillageKEM", "KEM_PARAMS",
           "Brume1024", "BRUME1024_PROFILES", "Brume1024P", "BRUME1024P_PROFILES", "brume1024_hash", "brume1024_xof",
           "Brume1024TagError", "Brume1024TamperError",
           "SillageSIG", "SIG_PARAMS", "SillageVOLE"]
