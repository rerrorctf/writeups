#!/usr/bin/env sage

from itertools import product
from string import ascii_letters

p = 730750818665451459112596905638433048232067471723
a = 425706413842211054102700238164133538302169176474
b = 203362936548826936673264444982866339953265530166

E = EllipticCurve(GF(p), [a, b])

P0 = E.lift_x(344338284117963723703790671118658790497555124168)
# (344338284117963723703790671118658790497555124168 : 299247302786516342875640670883006145903525200231 : 1)

P = [P0[0]]
# [344338284117963723703790671118658790497555124168]

v = [344338284117963723703790671118658790497555124168,
    0,
    651277720123486161075689024333545407539538157640,
    500080632050259613269921934837973984254718648438,
    683211176955383769290398013608858348596484221573,
    37103301988693271924307570949844036347800545475]

# flag starts with pearl{ so flag[0:0+5].encode() is b"pearl"
# int.from_bytes(b"pearl", byteorder="big") => 482737222252

# therefore the first loop does 482737222252 * E.lift_x(344338284117963723703790671118658790497555124168)
# (260447762554553251289922391132710160711408253100 : 287647263905849746687673733989246770792331331885 : 1)

v[1] = (int.from_bytes(b"pearl", byteorder="big") * E.lift_x(v[0]))[0]

# so in order to figure out the next 5 bytes of the flag we must work out n given
# 651277720123486161075689024333545407539538157640 = (n * E.lift_x(260447762554553251289922391132710160711408253100))[0]

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

flag = b""
flag += int(SmartAttack(E.lift_x(v[0]), E.lift_x(v[1]), p)).to_bytes(length=5, byteorder="big")

# not sure why this doesn't work..
# print(int(SmartAttack(E.lift_x(v[1]), E.lift_x(v[2]), p))) # 730750818665451459112596905638433047701849946105

# we know this section starts with {
# based on the rest of flag - pearl{????t4ss_b3ats_3cc} - the first word is probably a variation on smartass
# something like {s... or {S... or {$...

alphabet = ascii_letters + "0123456789"
permutations = [''.join(p) for p in product(alphabet, repeat=3)]
for permutation in permutations:
    n = int.from_bytes(b"{s" + permutation.encode(), byteorder="big")
    if (n * E.lift_x(v[1]))[0] == v[2]:
        flag += n.to_bytes(length=5, byteorder="big")
        break

flag += int(SmartAttack(E.lift_x(v[2]), E.lift_x(v[3]), p)).to_bytes(length=5, byteorder="big")
flag += int(SmartAttack(E.lift_x(v[3]), E.lift_x(v[4]), p)).to_bytes(length=5, byteorder="big")
flag += int(SmartAttack(E.lift_x(v[4]), E.lift_x(v[5]), p)).to_bytes(length=5, byteorder="big")

print(flag.decode()) # pearl{smart4ss_b3ats_3cc}
