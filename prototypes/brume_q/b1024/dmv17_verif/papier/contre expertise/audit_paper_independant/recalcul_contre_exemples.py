from fractions import Fraction as F
from math import comb, factorial
from decimal import Decimal, localcontext
from itertools import product
import sympy as sp
z=sp.symbols('z')
def g(n):
 v=1
 for i in range(n):v*=1-i*z
 return v
expr=1-sum(F(comb(8,i),256)*g(max(i,8-i)+1)*g(min(i,8-i)) for i in range(9))
print('hand polynomial:', sp.Poly(sp.expand(expr),z))
print('matches:',sp.expand(expr-(F(611,32)*z-154*z**2+F(10927,16)*z**3-F(29029,16)*z**4+F(94199,32)*z**5-F(45351,16)*z**6+1473*z**7-315*z**8))==0)

def pi0_upper(mu,r,c):
 b=r+c
 x=F(comb(mu,2),2**r)
 s=sum((x**n/F(factorial(n))) for n in range(60))
 return 1/((1-F(mu*mu,2**b))*s)
def nu_upper(N,r,c):
 for nu in range(1,100):
  if F(comb(N,nu+1),2**(r*nu)) <= F(nu,2**c): return nu
 raise ValueError('nu not found')

def mainrow(b,r,c,k,mu,omega,v):
 M=mu+v+v*omega+1
 gamma=F(2**b,2**b-M)
 nu=nu_upper(2*M,r,c)
 mu_bar=1+gamma*F(comb(mu,2),2**r)
 rho=gamma*F(comb(M,2),2**b)+gamma/F(2**c)*(omega*(1+mu_bar)+comb(omega,2)+gamma*F(v*omega+(v-1)*comb(omega,2),2**r))
 if mu<=1000:
  pi=F(1,1)
  for i in range(1,mu): pi*=F(2**b-i*2**c,2**b-i)
 else:
  pi=pi0_upper(mu,r,c)
 phi=F(comb(omega,2)+omega*(1+F(comb(mu,2),2**r)),2**(v*r))
 LB=(comb(omega+1,2)*(1-rho)+omega*(1-pi-rho))/2**c - F(omega*M,2**b) -phi
 B=F(2*nu+comb(omega+1,2),2**c)+F(M-1,2**b-1)+F(M*(M-1),2**b)+F(M-1,2**(k+min(c,b-k)))
 B2=F(comb(omega+1,2),2**c)+F(M*(M-1),2**b)
 with localcontext() as ctx:
  ctx.prec=35
  d=lambda q: str(Decimal(q.numerator)/Decimal(q.denominator))
  print('r,c,k',r,c,k,'Mu,omega,v',mu,omega,v,'M',M,'nu',nu,'pi0',d(pi),'rho',d(rho),'phi',d(phi),'LB*2^c',d(LB*2**c),'B2',d(B2*2**c),'B',d(B*2**c),'ratio',d(LB/B),'margin',d((LB-B)*2**c), 'verified', LB>B and LB>B2)
for args in [(36,16,20,16,640,64,2),(36,16,20,16,768,48,2),(64,24,40,24,3*2**12,64,3),(96,32,64,32,3*2**16,64,3),(320,64,256,128,3*2**32,64,5)]: mainrow(*args)
