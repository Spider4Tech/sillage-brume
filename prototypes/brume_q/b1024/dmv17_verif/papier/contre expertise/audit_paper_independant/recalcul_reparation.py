from fractions import Fraction as F
from math import comb, log2
for b,r,c,k,mu,o,v,orig in [(36,16,20,16,640,64,2,2099.082),(36,16,20,16,768,48,2,1197.483),(64,24,40,24,3*2**12,64,3,2099.290),(96,32,64,32,3*2**16,64,3,2101.018),(320,64,256,128,3*2**32,64,5,2109.000)]:
 M=mu+v+v*o+1
 def beta(m):return F(comb(M,m+1),2**((r-1)*m)) if m<M else F(0)
 Lam=F(comb(o+1,2),2**c) +F(o*comb(M,2)+2*comb(M,2),2**b) # C=L+omega, M-L=M so Lambda
 C0=F(M-1,2**b-1)+F(M-1,2**(k+min(c,b-k)))
 vals=[(m,2*beta(m)+2*Lam+C0) for m in range(1,60)]
 m_best,Bprime=min(vals,key=lambda t:t[1]); mcut=next(m for m in range(1,60) if beta(m)<=F(m,2**c))
 print('b r c',b,r,c,'mcut',mcut,'mopt',m_best,'B_prime * 2^c',float(Bprime*2**c),'origB*2^c',orig,'ratio',float(Bprime*2**c)/orig,'bit_gap',log2(float(Bprime*2**c)/orig),'beta*m',float(beta(m_best)*2**c))
