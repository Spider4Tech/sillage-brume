"""Independent re-implementation (pure Python, other generator, dictionaries) of the distinguisher D of thm1_distinguisher.c,
written from the description in the paper, to cross-check the C program on a small model.
The construction is coded as Algorithm 1 of DMV17 (class KD), the adversary only sees the outputs Z.
Usage: thm1_distinguisher_check.py r c k Mu Omega v trials seed real|ideal"""
import random, sys
from math import sqrt

class KD:                                   # Algorithm 1 of DMV17, f a lazily sampled random permutation, one key
    def __init__(self, r, c, k, rng):
        self.r, self.c, self.b, self.rng = r, c, r + c, rng
        self.f, self.used = {}, set()
        self.K = rng.getrandbits(k); self.k = k
    def perm(self, x):
        if x not in self.f:
            while True:
                y = self.rng.getrandbits(self.b)
                if y not in self.used: break
            self.used.add(y); self.f[x] = y
        return self.f[x]
    def _out(self, sigma, flag):
        Z = self.s >> self.c
        if flag: sigma ^= Z << self.c
        self.s ^= sigma
        return Z
    def init(self, iv, sigma, flag):
        self.s = self.perm((self.K << (self.b - self.k)) | iv); return self._out(sigma, flag)
    def duplexing(self, sigma, flag):
        self.s = self.perm(self.s); return self._out(sigma, flag)

class IXIF:                                 # Algorithm 2: all the paths of D are distinct, so every Z is fresh and uniform
    def __init__(self, r, c, k, rng): self.r, self.rng = r, rng
    def init(self, iv, sigma, flag): return self.rng.getrandbits(self.r)
    def duplexing(self, sigma, flag): return self.rng.getrandbits(self.r)

def D(O, r, c, Mu, Om, v):
    Z = [None, O.init(0, 0, False)] + [O.duplexing(0, False) for _ in range(Mu + v - 1)]     # Z[1 .. Mu+v]
    count = {}
    for z in Z[1:Mu + 1]: count[z] = count.get(z, 0) + 1
    m = max(count.values()); alpha = min(z for z in count if count[z] == m)
    targets = [i for i in range(1, Mu + 1) if Z[i] == alpha]
    for l in range(Om):
        a = len(Z); Z.append(O.duplexing(alpha << c, True))
        for _ in range(v - 1): Z.append(O.duplexing(0, False))
        targets.append(a)
    Z.append(O.duplexing(0, False))
    flagged = targets[m:]
    for l, a in enumerate(flagged):
        for x in targets[:m + l]:
            if all(Z[x + h] == Z[a + h] for h in range(1, v + 1)): return 1
    return 0

if __name__ == "__main__":
    r, c, k, Mu, Om, v, trials, seed = map(int, sys.argv[1:9]); world = sys.argv[9]
    rng = random.Random(seed); ones = 0
    for _ in range(trials):
        ones += D((KD if world == "real" else IXIF)(r, c, k, rng), r, c, Mu, Om, v)
    p = ones / trials
    print(f"{world} r={r} c={c} k={k} Mu={Mu} Omega={Om} v={v} M={Mu + v + v * Om + 1} trials={trials} seed={seed} : Pr[D=1] = {p:.6e} +- {sqrt(p * (1 - p) / trials):.1e}")
