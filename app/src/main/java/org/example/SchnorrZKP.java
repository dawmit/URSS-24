package org.example;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;


class SchnorrZKP {
    
    private final ECPoint V;
    private final BigInteger r;

    public SchnorrZKP(ECPoint V, BigInteger r) 
    {
        this.V = V;
        this.r = r;
    }
    
    ECPoint getV() {
        return V;
    }
    
    BigInteger getr() {
        return r;
    }
}