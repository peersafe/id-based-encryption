package org.suai.idbased;

import java.io.PrintWriter;
import java.math.BigInteger;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
public class DecryptException extends Exception {

    BigInteger s;
    BigInteger secret_key;
    BigInteger MPK;

    DecryptException(BigInteger s, BigInteger secret_key, BigInteger MPK) {
        this.s = s;
        this.secret_key = secret_key;
        this.MPK = MPK;
    }

    public void writeParam(PrintWriter fout) {

        fout.write("S+2r = " + this.s.toString() + " Secret Key = " + this.secret_key.toString() + " MPK = " + this.MPK.toString() + "\n");


    }
}
