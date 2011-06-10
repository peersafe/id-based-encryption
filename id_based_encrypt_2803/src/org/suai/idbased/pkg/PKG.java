package org.suai.idbased.pkg;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import org.suai.idbased.util.ResidueCalculation;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author alex_neigum
 */
public class PKG {

    private BigInteger MPK;
    //public BigInteger MSK;
    private BigInteger P, Q;
    private int security;
    private long e = 65537;
    private BigInteger d;
    //   public BigInteger SSK;

    public PKG(int size)
    {
        security = size;
    }

    public PKG()
    {
    }
    public void init (BigInteger MPK, BigInteger P, BigInteger Q) {
        this.MPK = MPK;
        this.P = P;
        this.Q = Q;
        this.getSecretExponent();
    }
    public BigInteger getMPK () {
        return this.MPK;
    }
    public BigInteger getMSK1 () {
        return this.P;
    }
    public BigInteger getMSK2() {
        return this.Q;
    }
    public long getSigningPublicKey () {
        return this.e;
    }


    public void setup()
    { // генерация M = P*Q
        BigInteger tree = BigInteger.valueOf(3);
        BigInteger four = BigInteger.valueOf(4);
        BigInteger signOpenExp = BigInteger.valueOf(e);


        // генерим P
        while (true)
          {
            P = BigInteger.probablePrime(security, new Random());
            Q = BigInteger.probablePrime(security, new Random());
            if (P.compareTo(Q) != 0 && P.mod(four).compareTo(tree) == 0 && Q.mod(
                    four).compareTo(tree) == 0 && signOpenExp.gcd(ResidueCalculation.
                    euler(P, Q)).compareTo(BigInteger.ONE) == 0)
              {
                break;
              }
          }
        MPK = P.multiply(Q);
        this.getSecretExponent();

    }

    static public BigInteger genPkID(String id, BigInteger P, BigInteger Q,
                              BigInteger MPK) throws NoSuchAlgorithmException
    {
        int i = 0;
        BigInteger a;
        int j = 0;
        int k = 0;
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(id.getBytes());
        byte[] hash = md.digest();
        a = new BigInteger(hash);
        a = a.abs();
        a = a.mod(MPK);


        while (true)
          {
            j = ResidueCalculation.Jacobi(a, P);
            k = ResidueCalculation.Jacobi(a, Q);
            if (j == -1 && k == -1)
              {

                return MPK.subtract(a);

              }
            else if (j == 1 && k == 1)
              {
                return a;
              }
            else
              {
                a = a.add(BigInteger.ONE);
              }
          }
    }

    public BigInteger keyExtract(String id) throws NoSuchAlgorithmException
    {  //генерация секретного ключа id
        BigInteger SKE;
        BigInteger a = genPkID(id, P, Q, MPK);



        BigInteger exp = MPK.add(BigInteger.valueOf(5)).subtract(P.add(Q)).
                divide(BigInteger.valueOf(8));

        SKE = a.modPow(exp, MPK);



        return SKE;

    }

    private void getSecretExponent()
    {
        BigInteger phi = ResidueCalculation.euler(P, Q);
        this.d = BigInteger.valueOf(e).modInverse(phi);

    }

    public BigInteger signKeyExtract(String id) throws NoSuchAlgorithmException
    {
        BigInteger SKS;
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(id.getBytes());
        byte[] hash = md.digest();
        BigInteger _id = new BigInteger(hash);
        SKS = _id.modPow(d, MPK);
        return SKS;


    }
}
