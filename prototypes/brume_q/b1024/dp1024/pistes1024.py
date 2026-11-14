# -*- coding: utf-8 -*-
"""tests/pistes_monomiales.py (construction et vérification de pistes monomiales) appliqué à BRUME-1024q : le source
de la suite est chargé tel quel, seul le module de paramètres change (b1024_module au lieu de sillage.brume512).
`import pistes1024` rend directement ce module (il se remplace dans sys.modules).
Aucune règle n'est réécrite : `verifier`, les tables de monômes et la couche linéaire binaire sont ceux de la suite."""
import os
import sys
import types

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)
import b1024_module  # noqa: E402

_SRC = os.path.normpath(os.path.join(_ICI, "..", "..", "..", "..", "tests", "pistes_monomiales.py"))
_LIGNE = "from sillage import brume512 as B"
_texte = open(_SRC).read()
assert _texte.count(_LIGNE) == 1
mod = types.ModuleType("pistes1024")
mod.__file__ = _SRC
sys.modules["pistes1024"] = mod
exec(compile(_texte.replace(_LIGNE, "import b1024_module as B"), _SRC, "exec"), mod.__dict__)
