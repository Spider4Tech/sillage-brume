"""Independent re-implementation (pure Python, dictionaries, other generator) of the experiment of f3_rd.c, written
from Algorithm 3 of DMV17 (class RD) and from the description of the adversary in the paper.
Usage: f3_rd_check.py r c Omega F v T_fw trials seed"""
import random, sys
from math import sqrt

class RD:                                        # Algorithm 3 of DMV17: phi and pi lazily sampled
    def __init__(self, r, c, rng):
        self.r, self.c, self.b, self.rng = r, c, r + c, rng
        self.phi, self.phi_used, self.pi, self.pi_used = {}, set(), {}, set()
        self.outer_parts = []                    # outer part of the state after each injection (to compute mu_fw)
    def _lazy(self, table, used, x):
        if x not in table:
            while True:
                y = self.rng.getrandbits(self.b)
                if y not in used: break
            used.add(y); table[x] = y
        return table[x]
    def _out(self, sigma, flag):
        Z = self.s >> self.c
        if flag: sigma ^= Z << self.c
        self.s ^= sigma
        self.outer_parts.append(self.s >> self.c)
        return Z
    def init(self, delta, iv, sigma, flag):
        self.s = self._lazy(self.phi, self.phi_used, (delta, iv)); return self._out(sigma, flag)
    def duplexing(self, sigma, flag):
        self.s = self._lazy(self.pi, self.pi_used, self.s); return self._out(sigma, flag)

def adversary(O, c, Om, F, v):
    Z = [None, O.init(0, 0, 0, False)]                                  # query 1
    for _ in range(Om): Z.append(O.duplexing(0, True))                  # queries 2 .. Om+1, outer part forced to 0
    p = 0
    for jj in range(3, Om + 3 - v):                                     # windows Z[jj .. jj+v-1] inside Z[2 .. Om+1]
        for ii in range(2, jj):
            if Z[jj:jj + v] == Z[ii:ii + v]: p = jj - ii; break
        if p: break
    for _ in range(F):
        n = len(Z)                                                      # index of the query about to be made
        Z.append(O.duplexing((Z[n - p] << c) if p else 0, False))

if __name__ == "__main__":
    r, c, Om, F, v, Tfw, trials, seed = map(int, sys.argv[1:9])
    rng = random.Random(seed); succ = 0
    for _ in range(trials):
        O = RD(r, c, rng); adversary(O, c, Om, F, v)
        cnt = {}
        for x in O.outer_parts: cnt[x] = cnt.get(x, 0) + 1
        succ += max(cnt.values()) > Tfw
    p = succ / trials
    print(f"r={r} c={c} Omega={Om} F={F} v={v} T_fw={Tfw} trials={trials} seed={seed} : Pr_P(mu_fw > T_fw) = {p:.5f} +- {sqrt(p * (1 - p) / trials):.5f}")
