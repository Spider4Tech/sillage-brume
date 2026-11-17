from math import comb
from fractions import Fraction as F

def no_high(n, bins, m):
 dp=[0]*(n+1);dp[0]=1
 for j in range(bins):
  d=[0]*(n+1)
  for t,a in enumerate(dp):
   if not a:continue
   for k in range(min(m,n-t)+1):d[t+k]+=a*comb(t+k,k)
  dp=d
 return F(dp[n],bins**n)
def vcal(N,r,c):
 B=2**r
 for x in range(1,15):
  p=1-no_high(N,B,x)
  print('N',N,'r',r,'c',c,'x',x,'p-tail approx',float(p),'limit',x/2**c,'pass',p<=F(x,2**c),flush=True)
  if p<=F(x,2**c):return x
for p in [(22,4,12),(20,4,10),(74,8,12)]:print('nu=',vcal(*p))
