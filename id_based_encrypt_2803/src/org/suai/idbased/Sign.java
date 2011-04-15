package org.suai.idbased;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
public class Sign {

    public BigInteger[] getSign(byte[] message, BigInteger skey, long pkey, BigInteger MPK) throws NoSuchAlgorithmException {
        Random rand = new Random();

        BigInteger r = new BigInteger(MPK.bitLength(), rand);
        r = r.mod(MPK);

        BigInteger T = r.modPow(BigInteger.valueOf(pkey), MPK);

        byte[] data = new byte[message.length + T.toByteArray().length];
        System.arraycopy(message, 0, data, 0, message.length);
        System.arraycopy(T.toByteArray(), 0, data, message.length, T.toByteArray().length);
        MessageDigest MD = MessageDigest.getInstance("SHA");
        MD.update(data);
        byte[] hash = MD.digest();
        BigInteger exp = new BigInteger(hash);
        exp = exp.abs();

        BigInteger s = skey.multiply(r.modPow(exp, MPK));
        s = s.mod(MPK);

        BigInteger[] sign = new BigInteger[2];
        sign[0] = T;
        sign[1] = s;
        return sign;
    }

    public boolean verifySign(byte[] message, String id, BigInteger[] sign, long pkey, BigInteger MPK) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(id.getBytes());
        byte[] hash = md.digest();
        BigInteger _id = new BigInteger(hash);
        md.reset();

        byte[] data = new byte[message.length + sign[0].toByteArray().length];
        System.arraycopy(message, 0, data, 0, message.length);
        System.arraycopy(sign[0].toByteArray(), 0, data, message.length, sign[0].toByteArray().length);
        MessageDigest MD = MessageDigest.getInstance("SHA");
        MD.update(data);
        hash = MD.digest();
        BigInteger exp = new BigInteger(hash);
        exp = exp.abs();

        BigInteger verify = _id.multiply(sign[0].modPow(exp, MPK));
        verify = verify.mod(MPK);
        return verify.equals(sign[1].modPow(BigInteger.valueOf(pkey), MPK));







    }
}
