
package org.example;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;

public class ECCJPAKECurve
{
    private final ECCurve.Fp curve;
	private final BigInteger a;
	private final BigInteger b;
	private final BigInteger q;
	private final BigInteger h;
	private final BigInteger n;
	private final ECPoint g;

    public ECCJPAKECurve(BigInteger a, BigInteger b, BigInteger q, BigInteger h, BigInteger n, ECPoint g, ECCurve.Fp curve)
    {
        /**
         * Don't skip the checks on user-specified groups.
         */
        this(a, b, q, h, n, g, curve, false);
    }

    ECCJPAKECurve(BigInteger a, BigInteger b, BigInteger q, BigInteger h, BigInteger n, ECPoint g, ECCurve.Fp curve, boolean skipChecks)
    {
        ECCJPAKEUtil.validateNotNull(a, "a");
        ECCJPAKEUtil.validateNotNull(b, "b");
        ECCJPAKEUtil.validateNotNull(q, "q");
        ECCJPAKEUtil.validateNotNull(h, "h");
        ECCJPAKEUtil.validateNotNull(n, "n");
        ECCJPAKEUtil.validateNotNull(g, "g");
        ECCJPAKEUtil.validateNotNull(curve, "curve");

        if (!skipChecks)
        {
            if(!q.isProbablePrime(20)) {
                throw new IllegalArgumentException("Field size q must be prime"); //q must also be odd make sure of this
            }

            if(!n.isProbablePrime(20)) {
                throw new IllegalArgumentException("The order n must be prime");
            }

            if((a.pow(3).multiply(BigInteger.valueOf(4)).add(b.pow(2).multiply(BigInteger.valueOf(27))).mod(q)) == BigInteger.valueOf(0)) {
                throw new IllegalArgumentException("The curve is singular, i.e the discriminant is equal to 0 mod q.");
            }

            try {
                curve.decodePoint(g.getEncoded(true)); //Maybe use isValid() from ECPoint
            } catch(Exception e) {
                throw new IllegalArgumentException("G does not lie on the curve", e);
            }

            BigInteger totalPoints = n.multiply(h);
            if(!totalPoints.equals(curve.getOrder())) {
                throw new IllegalArgumentException("n is not equal to the order of your curve");
            }

            if(a.compareTo(BigInteger.ZERO) == -1 || a.compareTo(q.subtract(BigInteger.ONE)) == 1) {
                throw new IllegalArgumentException("The parameter 'a' is not in the field [0, q-1]");
            }

            if(b.compareTo(BigInteger.ZERO) == -1 || b.compareTo(q.subtract(BigInteger.ONE)) == 1) {
                throw new IllegalArgumentException("The parameter 'b' is not in the field [0, q-1]");
            }
        }

        this.a = a;
        this.b = b;
        this.h = h;
        this.n = n;
        this.q = q;
        this.g = g;
        this.curve = curve;
    }

    public BigInteger getA()
    {
        return a;
    }

    public BigInteger getB()
    {
        return b;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public ECPoint getG()
    {
        return g;
    }

    public ECCurve.Fp getCurve()
    {
        return curve;
    }


}
