package org.suai.idbased;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
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
    void signFile (String in, String out, String id, BigInteger SKS, BigInteger MPK, long PKS) throws NoSuchAlgorithmException, IOException {
        FileInputStream fin = new FileInputStream (in);
        FileOutputStream fout = new FileOutputStream (out);
        DataOutputStream dos = new DataOutputStream (fout);
        byte [] data = new byte [fin.available()];
        fin.read(data);
        BigInteger[] sign = this.getSign(data, SKS, PKS, MPK);
        dos.writeInt (id.length());
        dos.writeChars(id);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
        dos.write(data);
        dos.close();

    }
    boolean verifySignedFile (String in, long pkey, BigInteger MPK) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        FileInputStream fin = new FileInputStream (in);
        DataInputStream din = new DataInputStream (fin);
        int data_size = din.available();
        int id_size = din.readInt();
        boolean verify_sign;
        StringBuffer sb = new StringBuffer ();
        for (int i = 0; i < id_size; i++) {
            sb.append(din.readChar());

        }
        String id = sb.toString();
        System.out.println ("Файл подписан:"+id);

        int size_of_t = din.readInt();
        int size_of_s = din.readInt();
        byte[] t_byte = new byte[size_of_t];
        byte[] s_byte = new byte[size_of_s];
        din.read(t_byte);
        din.read(s_byte);
        BigInteger[] sign = new BigInteger[2];
        BigInteger t = new BigInteger(t_byte);
        BigInteger S = new BigInteger(s_byte);
        sign[0] = t;
        sign[1] = S;
        data_size = din.available();
        byte [] data = new byte [data_size];
        din.read(data);
        verify_sign = this.verifySign(data, id, sign, pkey, MPK);

        if (verify_sign == false) {
            System.out.println ("Подпись неверна");
            return false;
        } else {
            System.out.println ("Подпись верна");
            return true;
        }



    }
}
