package org.suai.idbased;

import org.suai.idbased.Sign;
import org.suai.idbased.ResidueCalculation;
import org.suai.idbased.DecryptException;
import org.suai.idbased.Cryptocontainer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
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
 * @author alex_neigum
 */
public class Util {

    public static BigInteger genPkID(String id, BigInteger MPK) throws NoSuchAlgorithmException {
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
        while (true) {
            j = ResidueCalculation.Jacobi(a, MPK);

            if (j == 1) {
                return a;
            } else {
                a = a.add(BigInteger.ONE);
            }
        }
    }

    static StringBuffer KeyToBinary(byte[] raw) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < raw.length; i++) {
            String binary = null;
            binary = Integer.toBinaryString(raw[i] & 0xff);
            if (binary.length() < 8) {
                for (int k = 0; k < 8 - binary.length(); k++) {
                    sb.append("0");
                }
            }
            sb.append(binary);

        }
        return sb;
    }

    static void EncryptKey(StringBuffer sb, BigInteger[] ciphertext, BigInteger[] inv_ciphertext, BigInteger MPK, BigInteger PkID) {
        int m = 0;
        int j = 0;
        BigInteger inv_t;
        BigInteger t;
        BigInteger b;
        Random rand = new Random();
        int length = MPK.bitLength() / 4;
        for (int i = 0; i < sb.length(); i++) {
            m = Character.digit(sb.charAt(i), 10);


            while (true) {
                t = new BigInteger(length, rand);
                t = t.mod(MPK);
                j = ResidueCalculation.Jacobi(t, MPK);
                //+1 = 1; -1 = 0
                if (m == 0 && j == -1) {
                    inv_t = t.modInverse(MPK);
                    b = PkID.multiply(inv_t);
                    ciphertext[i] = t.add(b).mod(MPK);
                    inv_ciphertext[i] = t.subtract(b).mod(MPK);
                    break;
                } else if (m == 1 && j == 1) {
                    inv_t = t.modInverse(MPK);
                    b = PkID.multiply(inv_t);
                    ciphertext[i] = t.add(b).mod(MPK);
                    inv_ciphertext[i] = t.subtract(b).mod(MPK);
                    break;

                }
            }

        }

    }

    static void WriteEncryptedData(DataOutputStream dos, BigInteger[] ciphertext, BigInteger[] inv_ciphertext, byte[] encrypted_data) throws IOException {
        int key_size1 = 0;
        int key_size2 = 0;
        for (int i = 0; i < ciphertext.length; i++) {
            key_size1 = key_size1 + ciphertext[i].toByteArray().length;
        }
        for (int i = 0; i < inv_ciphertext.length; i++) {
            key_size2 = key_size2 + inv_ciphertext[i].toByteArray().length;
        }
        dos.writeInt(key_size1 + 128 * 4); //записываем длину 1го ключа
        dos.writeInt(key_size2 + 128 * 4); //записываем длину 2го ключа

        //записываем ключевую информацию
        for (int i = 0; i < ciphertext.length; i++) {
            dos.writeInt(ciphertext[i].toByteArray().length);
            dos.write(ciphertext[i].toByteArray());
        }

        for (int i = 0; i < inv_ciphertext.length; i++) {
            dos.writeInt(inv_ciphertext[i].toByteArray().length);
            dos.write(inv_ciphertext[i].toByteArray());
        }

        int encrypted_data_size = encrypted_data.length;
        dos.writeInt(encrypted_data_size);
        dos.write(encrypted_data);
    }

    static void WriteSignature(FileInputStream fis, DataOutputStream dos, Sign signature, BigInteger MPK, BigInteger sk, long pk) throws IOException, NoSuchAlgorithmException {

        byte[] data_to_hash = new byte[fis.available()];
        fis.read(data_to_hash);
        BigInteger[] sign = new BigInteger[2];
        sign = signature.getSign(data_to_hash, sk, pk, MPK);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
    }

    static Cryptocontainer GetCryptocontainerParameters(FileInputStream fin, DataInputStream ds) throws IOException {
        Cryptocontainer cc = new Cryptocontainer();
        int data_size = fin.available();
        int key_size1 = ds.readInt();
        int key_size2 = ds.readInt();
        if (ds.available() < key_size1 + key_size2) {
            return null;
        }
        ds.skipBytes(key_size1 + key_size2);
        int encrypted_data_size = ds.readInt();
        int sign_length = data_size - key_size1 - key_size2 - encrypted_data_size - 12;
        int check = cc.writeParam(data_size, key_size1, key_size2, encrypted_data_size, sign_length);
        if (check == -1) {
            return null;
        }
        return cc;


    }

    static Object ReadSignature(DataInputStream ds, Sign signature, String id, byte[] data, long pkey, BigInteger MPK) throws NoSuchAlgorithmException, IOException {
        boolean verify_sign;
        int size_of_t = ds.readInt();
        int size_of_s = ds.readInt();
        byte[] t_byte = new byte[size_of_t];
        byte[] s_byte = new byte[size_of_s];
        ds.read(t_byte);
        ds.read(s_byte);
        BigInteger[] sign = new BigInteger[2];
        BigInteger t = new BigInteger(t_byte);
        BigInteger S = new BigInteger(s_byte);
        sign[0] = t;
        sign[1] = S;
        verify_sign = signature.verifySign(data, id, sign, pkey, MPK);

        if (verify_sign == false) {
            return null;
        } else {
            return 1;
        }
    }

    static void GetEncryptedKey(DataInputStream din, boolean keytype, Cryptocontainer cc, BigInteger[] encrypted_aes_key) throws IOException {
        int size_of_encr_keybyte;
        din.skipBytes(8);
        if (keytype == false) {
            for (int i = 0; i < 128; i++) {
                size_of_encr_keybyte = din.readInt();

                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);


            }
            din.skipBytes(cc.secondKeySize);
        } else {
            din.skipBytes(cc.firstKeySize);
            for (int i = 0; i < 128; i++) {
                size_of_encr_keybyte = din.readInt();
                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);

            }
        }
    }

    static int[] DecryptKey(BigInteger[] encrypted_aes_key, BigInteger SkID, BigInteger MPK) throws DecryptException {
        int[] binary_aes_key = new int[128];
        int Jacobi;
        BigInteger root = SkID.multiply(BigInteger.valueOf(2)).mod(MPK);
        for (int i = 0; i < 128; i++) {
            Jacobi = ResidueCalculation.Jacobi(encrypted_aes_key[i].add(root), MPK);

            if (Jacobi == 1) {
                binary_aes_key[i] = 1;
            } else if (Jacobi == -1) {
                binary_aes_key[i] = 0;
            } else {
                binary_aes_key[i] = 0; // error
                throw new DecryptException(encrypted_aes_key[i].add(SkID.multiply(BigInteger.valueOf(2))).mod(MPK), SkID, MPK);
            }
        }
        return binary_aes_key;
    }

    static byte[] BinaryToByteKey(int[] binary_aes_key) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < binary_aes_key.length; i++) {
            sb.append(binary_aes_key[i]);
        }

        int from = 0, to = 8;
        String byte_of_key = new String();
        byte[] raw = new byte[16];
        String aes_key = sb.toString();
        for (int i = 0; i < 16; i++) {
            byte_of_key = aes_key.substring(from, to);


            raw[i] = Integer.valueOf(byte_of_key, 2).byteValue();
            from = to;
            to = to + 8;
        }
        return raw;
    }
}
