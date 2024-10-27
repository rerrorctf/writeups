https://ctftime.org/event/2496

# Interpolation (crypto)

Has missing data really ever stopped anyone ?

nc crypto.heroctf.fr 9000

## Analysis

We can see that the task implements https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing

```python
F = FiniteField(2**256 - 189)
R = PolynomialRing(F, "x")
H = lambda n: int(hashlib.sha256(n).hexdigest(), 16)
C = lambda x: [H(x[i : i + 4]) for i in range(0, len(FLAG), 4)]
f = R(C(FLAG))
```

We know that Lagrange polynomial interpolation can perfectly recover a polynomial of degree n with n points.

Normally the points are shared between the different entities in the secret sharing arrangement.

This means that only once the shares are combined can the entire secret be recovered.

However in this case we have all of the shares and so we can recover the original polynomial.

Once we have the polynomial coefficients it is just a case of computing SHA2-256 preimages for them.

Normally this would be hard but we have a very limited input domain.

## Solution

1) Collect points from the remote ( see points.txt for the points I collected and used )
    - Note: I had to collect multiple sets of points and combine from the remote before getting the correct coefficients from the interpolation
2) Perform Lagrange polynomial interpolation on the points in the polynomial ring
3) Collect the coefficients

```python
#!/usr/bin/sage

F = FiniteField(2**256 - 189)
R = PolynomialRing(F, "x")

# points = removed for compactness ~ see points.txt for collected points

print(R.lagrange_polynomial(points).coefficients())
```

1) Compute the SHA2-256 of every 4 character permutation of the alphabet
2) For each coefficient recover the 4 character preimage

```python
#!/usr/bin/env python3

from itertools import product
from string import ascii_letters
from hashlib import sha256

coefficients = [
    51862623363251592162508517414206794722184767070638202339849823866691337237984,
    37382279584575671665412736907293996338695993273870192478675632069138612724862,
    54922548012150305957596790093591596584466927559339793497872781061995644787934,
    78252810134582863205690878209501272813895928209727562041762503202357420752872,
    42828444749577646348433379946210116268681295505955485156998041972023283883825,
    16605552275238206773988750913306730384585706182539455749829662274657349564685,
    10009681240064642703458239750230614173777134131788316383198404412696086812123,
    78645989056858155953548111309497253790838184388240819797824701948971210482613,
    4244268215373067710299345981438357655695365045434952475766578691548900068884,
    4587316730151077745530345853110346550953429707066041958662730783235705675823,
    98676420105970876355731743378079563095438931888109560800924537433679751968410,
    15596341609452054024790211046165535925702287406391095849367220616094959319247,
    32403908412257070302225532346590438994349383666861558172214850130936584778364,
    115533839068795212658451397535765278473898133068309149603041276877934373391258,
    7092396080272228853132842491037895182885372693653833621714864119915575351959,
    66681440692524165569992671994842901187406728987456386756946647843877275534778,
    43594818259201189283635356607462328520192502107771693650896092861477784342431,
    91842050171741174464568525719602040646922469791657773826919079592778110767648,
    105484582062398143020926667398250530293520625898492636870365251172877956081489,
    48478433129988933656911497337570454952912987663301800112434018755270886790086,
    9286536496641678624961072298289256247776902880262474453231051084428770229931,
    71177914266346294875020009514904614231152252028035180341047573071890295627281,
    58688474918974956495962699109478986243962548972465028067725936901754910032197,
    91356407137791927144958613770622174607926961061379368852376771002781151613901]

alphabet = ascii_letters + "0123456789" + "{}_"
permutations = [''.join(p) for p in product(alphabet, repeat=4)]

hash_to_string = {}
for permutation in permutations:
    h = int(sha256(permutation.encode()).hexdigest(), 16)
    hash_to_string[h] = permutation

flag = ""
for coefficient in coefficients:
    flag += hash_to_string[coefficient]

print(flag) # Hero{th3r3_4r3_tw0_typ35_0f_p30pl3_1n_th15_w0rld_th053_wh0_c4n_3xtr4p0l4t3_fr0m_1nc0mpl3t3_d474}
```

## Flag
`Hero{th3r3_4r3_tw0_typ35_0f_p30pl3_1n_th15_w0rld_th053_wh0_c4n_3xtr4p0l4t3_fr0m_1nc0mpl3t3_d474}`

smiley 2024/10/26
