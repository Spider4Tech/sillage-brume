from math import factorial,comb
from fractions import Fraction
from sympy.utilities.iterables import partitions
B=16; C=65536
facts=[factorial(i) for i in range(72)]
def eval_row(mu,omega):
 g=[1]
 for n in range(1,mu+omega+1):g.append(g[-1]*(C-(n-1)))
 d=(B**mu)*(C**(mu+omega))
 weighted_sum_adaptive=weighted_sum_control=weighted_peak=0
 for dic in partitions(mu):
  n=sum(dic.values())
  if n>B:continue
  count=facts[B]//facts[B-n]
  count*=facts[mu]
  den=1
  for k,v in dic.items(): den*=facts[v]*facts[k]**v
  assert count%den==0
  count//=den
  gn=1
  for k,v in dic.items():gn*=g[k]**v
  peak=max(dic)
  tail=lambda k:g[k+omega]//g[k]
  weighted_sum_adaptive+=count*gn*tail(peak)
  ctrl=(B-n)*tail(0)+sum(v*tail(k) for k,v in dic.items())
  weighted_sum_control+=count*gn*ctrl
  weighted_peak+=count*peak
 P=Fraction(d-weighted_sum_adaptive,d)
 Q=Fraction(B*d-weighted_sum_control,B*d)
 W=Fraction(comb(mu+omega,2),2**20)+Fraction(comb(omega+1,2),2**16)
 Lambda_s=Fraction(comb(omega+1,2),2**16)+Fraction(omega*comb(mu,2)+comb(mu+omega,2),2**20)
 return [float(P),float(Q),float(W),float(P/W),float(Fraction(weighted_peak,B**mu)),float(Lambda_s)]
for mu,omega in [(4,8),(8,8),(16,1),(16,8),(24,16),(32,4),(40,2),(2,30)]:print(mu,omega,eval_row(mu,omega),flush=True)
