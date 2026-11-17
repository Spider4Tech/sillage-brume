from fractions import Fraction as F
from math import comb

def uppernu(n,r,c):
 for x in range(1,20):
  if F(comb(n,x+1),2**(r*x))<=F(x,2**c):return x
for b,r,c,v in [(36,16,20,3),(96,32,64,3),(320,64,256,5)]:
 for nu in range(1,20):
  Fcount=nu+1;M=1+v+Fcount
  if uppernu(2*M,r,c)==nu:break
 G=((2**c)//10-M-Fcount)//v
 bound=F(G,2**c)-G*(F(1,2**((r-1)*v))+F(4*v*v,2**b))-F(1,2**r)-F(v*(v+1),2**b)
 print('b r c v',b,r,c,v,'nu_upper',nu,'F',Fcount,'M',M,'G',G,'N+M',v*G+Fcount+M,'max',2**c//10,'bound',float(bound),'claimed threshold',float(F(nu,2**c)), 'bound>threshold',bound>F(nu,2**c))
