# -*- coding: utf-8 -*-
"""Détecteur statique (heuristique) du gadget « Speculative Store Bypass » créé par l'allocation des emplacements de pile.

Motif (enquête du 18 novembre 2026, docs/AUDIT_REPORT.md) : un même emplacement X(%rbp|%rsp) reçoit tantôt une DONNÉE
(registre produit par une opération logique entre registres, ou extrait d'un registre vectoriel), tantôt un POINTEUR qui
est relu puis utilisé comme base d'un accès mémoire. Si la relecture du pointeur passe spéculativement devant l'écriture
qui le restaure, elle reçoit la donnée par transfert depuis la file des écritures, et le cœur accède à une adresse tirée
de cette donnée : le temps dépend alors des données, même si le code est à temps constant au sens architectural.
C'est ce motif qui donnait le signal dudect du noyau portable inliné (GCC 13.3, -O3 -march=native, Zen 3).

Limites : analyse instruction par instruction, sans flot de contrôle ; une « donnée » n'est pas forcément secrète
(faux positifs possibles, à lire) ; un gadget qui passe par un autre motif (registre, autre forme d'adresse) n'est pas vu.
    python3 -m tests.gadget_ssb binaire_ou_objet [fonction ...]
"""
import re
import subprocess
import sys

SLOT = r"(-?0x[0-9a-f]+)\((%rbp|%rsp)\)"
REG64 = r"%[re]?[a-z0-9]+"   # tout registre entier ; ramené à son nom 64 bits par base()
_BASE32 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
           "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx", "si": "rsi", "di": "rdi",
           "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx", "sil": "rsi", "dil": "rdi"}


def base(reg):
    """%r12d, %r12w, %r12b → %r12 ; %eax, %ax, %al → %rax ; les autres inchangés."""
    r = reg.lstrip("%")
    m = re.match(r"(r[0-9]+)[dwb]$", r)
    return "%" + (m.group(1) if m else _BASE32.get(r, r))
LOGIQUE = ("xor", "and", "or", "andn", "not")
FENETRE = 12   # instructions examinées après la relecture d'un emplacement


def desassembler(chemin):
    """{fonction: [(adresse, instruction)]} pour tout le binaire ou l'objet."""
    asm = subprocess.run(["objdump", "-d", "--no-show-raw-insn", chemin], capture_output=True, text=True,
                         check=True).stdout
    fonctions, courante = {}, None
    for ligne in asm.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", ligne)
        if m:
            courante = fonctions.setdefault(m.group(1), [])
            continue
        p = ligne.split("\t")
        if courante is not None and len(p) >= 2 and p[1].strip():
            courante.append((p[0].strip().rstrip(":"), p[1].strip()))
    return fonctions


PROCHE = 128   # l'écriture qui restaure le pointeur doit précéder sa relecture d'au plus PROCHE instructions


def analyser(lignes):
    """Renvoie (emplacements « donnée », emplacements « pointeur », emplacements partagés avec leurs adresses).

    Un emplacement n'est retenu que dans l'ordre qui rend le contournement possible (ordre du listing, sans flot de
    contrôle) : écriture d'une donnée, puis écriture du pointeur, puis, à moins de PROCHE instructions de celle-ci,
    relecture du pointeur et déréférencement. Si le pointeur a été écrit bien avant, son écriture est résolue depuis
    longtemps et aucune relecture ne la contourne."""
    derniere_def, donnees, pointeurs = {}, {}, {}
    ecritures = {}   # emplacement -> liste (indice, adresse, est_donnee)
    for i, (adr, ins) in enumerate(lignes):
        mn = ins.split()[0]
        ops = ins[len(mn):].strip()
        ms = re.match(r"mov[lq]?\s+(" + REG64 + r")," + SLOT + "$", ins)
        if ms:
            slot = ms.group(2) + "(" + ms.group(3) + ")"
            est_donnee = derniere_def.get(base(ms.group(1))) == "donnee"
            ecritures.setdefault(slot, []).append((i, adr, est_donnee))
        elif re.search(r"," + SLOT + "$", ins):   # autre écriture (immédiate, lecture-modification-écriture)
            mm = re.search(r"," + SLOT + "$", ins)
            ecritures.setdefault(mm.group(1) + "(" + mm.group(2) + ")", []).append((i, adr, False))
        ml = re.match(r"mov\s+" + SLOT + r",(" + REG64 + r")$", ins)
        if ml:
            slot, reg = ml.group(1) + "(" + ml.group(2) + ")", base(ml.group(3))
            deref = None
            for adr2, ins2 in lignes[i + 1:i + 1 + FENETRE]:
                if re.match(r"(jmp|ret|ud2)\b", ins2):   # fin du bloc dans l'ordre du listing
                    break
                if "nop" in ins2.split()[0] or ins2.split()[0] == "lea":   # pas d'accès mémoire
                    continue
                if any(base(r) == reg for r in re.findall(r"\((%[a-z0-9]+)[,)]", ins2)):
                    deref = adr2
                    break
                md2 = re.search(r",(%[a-z0-9]+)$", ins2)
                if md2 and base(md2.group(1)) == reg:   # registre réécrit avant usage
                    break
            av = [e for e in ecritures.get(slot, []) if e[0] < i]
            # dernière écriture (le pointeur), proche, non « donnée » ; celle d'avant : une donnée
            if deref and len(av) >= 2 and not av[-1][2] and i - av[-1][0] <= PROCHE and av[-2][2]:
                donnees.setdefault(slot, []).append(av[-2][1])
                pointeurs.setdefault(slot, []).append((adr, deref))
        md = re.search(r",(" + REG64 + r")$", ins) or re.match(r"(?:not|neg|inc|dec)\s+(" + REG64 + r")$", ins)
        if md:
            srcs = [base(r) for r in re.findall(r"%[a-z0-9]+", ops)]
            zero = mn.startswith("xor") and len(srcs) == 2 and srcs[0] == srcs[1]   # mise à zéro
            donnee = ((mn.startswith(LOGIQUE) and "$" not in ops and not zero)
                      or (mn in ("vmovq", "movq", "vpextrq") and "%xmm" in ops))
            derniere_def[base(md.group(1))] = "donnee" if donnee else "autre"
    partages = {s: (donnees[s], pointeurs[s]) for s in sorted(pointeurs)}
    return donnees, pointeurs, partages


def analyser_fichier(chemin, fonctions=None):
    """{fonction: partages} pour les fonctions demandées (toutes par défaut), et le nombre de fonctions lues."""
    toutes = desassembler(chemin)
    choisies = fonctions or [f for f in toutes if not f.endswith("@plt") and toutes[f]]
    res = {}
    for f in choisies:
        if f in toutes:
            _, _, partages = analyser(toutes[f])
            if partages:
                res[f] = partages
    return res, len(choisies)


if __name__ == "__main__":
    res, n = analyser_fichier(sys.argv[1], sys.argv[2:] or None)
    print("%s : %d fonction(s) lues, %d avec un emplacement partagé" % (sys.argv[1], n, len(res)))
    for f, partages in res.items():
        for s, (d, p) in partages.items():
            print("  %s %s : donnée écrite en %s ; pointeur relu puis déréférencé en %s" % (
                f, s, ", ".join(d[:4]), ", ".join("%s→%s" % x for x in p[:4])))
