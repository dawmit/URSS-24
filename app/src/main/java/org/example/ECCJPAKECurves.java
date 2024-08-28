package org.example;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECCJPAKECurves 
{

    public static final ECCJPAKECurve NIST_P256;

    static{
        //a
        BigInteger a = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
        //b
        BigInteger b = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
        //q
        BigInteger q = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        //h
        BigInteger h = BigInteger.ONE;
        //n
        BigInteger n = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        //g
        ECCurve.Fp curve = new ECCurve.Fp(q, a, b, n, h);
        ECPoint g = curve.createPoint(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));

        NIST_P256 = new ECCJPAKECurve(a, b, q, h, n, g, curve, true);
    }


}