package org.suai.idbased;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
public class Client {

    public BigInteger genPkID(String id, BigInteger MPK) throws NoSuchAlgorithmException
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
            j = ResidueCalculation.Jacobi(a, MPK);

            if (j == 1)
              {
                return a;
              }
            else
              {
                a = a.add(BigInteger.ONE);
              }
          }
    }

    private void encryptKey(byte[] binaryKey, BigInteger[] ciphertext,
                            BigInteger[] inv_ciphertext, BigInteger MPK,
                            BigInteger PkID)
    {
        byte m = 0;
        int j = 0;
        BigInteger inv_t;
        BigInteger t;
        BigInteger b;
        Random rand = new Random();
        int length = MPK.bitLength() / 4;
        for (int i = 0; i < binaryKey.length; i++)
          {
            // m = Character.digit(sb.charAt(i), 10);
            m = binaryKey[i];


            while (true)
              {
                t = new BigInteger(length, rand);
                t = t.mod(MPK);
                j = ResidueCalculation.Jacobi(t, MPK);
                //+1 = 1; -1 = 0
                if ((m == 0 && j == -1) || (m == 1 && j == 1))
                  {
                    inv_t = t.modInverse(MPK);
                    b = PkID.multiply(inv_t);
                    ciphertext[i] = t.add(b).mod(MPK);
                    inv_ciphertext[i] = t.subtract(b).mod(MPK);
                    break;
                  }
//                } else if (m == 1 && j == 1) {
//                    inv_t = t.modInverse(MPK);
//                    b = PkID.multiply(inv_t);
//                    ciphertext[i] = t.add(b).mod(MPK);
//                    inv_ciphertext[i] = t.subtract(b).mod(MPK);
//                    break;
//
//                }
              }

          }

    }

    private void writeEncryptedData(DataOutputStream dos,
                                    BigInteger[] ciphertext,
                                    BigInteger[] inv_ciphertext,
                                    byte[] encrypted_data) throws IOException
    {
        int key_size1 = 0;
        int key_size2 = 0;
        for (int i = 0; i < ciphertext.length; i++)
          {
            key_size1 = key_size1 + ciphertext[i].toByteArray().length;
          }
        for (int i = 0; i < inv_ciphertext.length; i++)
          {
            key_size2 = key_size2 + inv_ciphertext[i].toByteArray().length;
          }
        dos.writeInt(key_size1 + 128 * 4); //записываем длину 1го ключа
        dos.writeInt(key_size2 + 128 * 4); //записываем длину 2го ключа

        //записываем ключевую информацию
        for (int i = 0; i < ciphertext.length; i++)
          {
            dos.writeInt(ciphertext[i].toByteArray().length);
            dos.write(ciphertext[i].toByteArray());
          }

        for (int i = 0; i < inv_ciphertext.length; i++)
          {
            dos.writeInt(inv_ciphertext[i].toByteArray().length);
            dos.write(inv_ciphertext[i].toByteArray());
          }

        int encrypted_data_size = encrypted_data.length;
        dos.writeInt(encrypted_data_size);
        dos.write(encrypted_data);
    }

    private void writeSignature(FileInputStream fis, DataOutputStream dos,
                                Sign signature, BigInteger MPK, BigInteger sk,
                                long pk) throws IOException, NoSuchAlgorithmException
    {

        byte[] data_to_hash = new byte[fis.available()];
        fis.read(data_to_hash);
        BigInteger[] sign = new BigInteger[2];
        sign = signature.getSign(data_to_hash, sk, pk, MPK);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
    }
     private void writeSignature(InputStream fis, DataOutputStream dos,
                                Sign signature, BigInteger MPK, BigInteger sk,
                                long pk) throws IOException, NoSuchAlgorithmException
    {

        byte[] data_to_hash = new byte[fis.available()];
        fis.read(data_to_hash);
        BigInteger[] sign = new BigInteger[2];
        sign = signature.getSign(data_to_hash, sk, pk, MPK);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
    }

    private boolean verifySignature(DataInputStream ds, Sign signature,
                                    String id, byte[] data, long pkey,
                                    BigInteger MPK) throws NoSuchAlgorithmException, IOException
    {
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

        if (verify_sign == false)
          {
            return false;
          }
        else
          {
            return true;
          }
    }

    private int[] decryptKey(BigInteger[] encrypted_aes_key, BigInteger SkID,
                             BigInteger MPK) throws DecryptException
    {
        int[] binary_aes_key = new int[128];
        int Jacobi;
        BigInteger root = SkID.multiply(BigInteger.valueOf(2)).mod(MPK);
        for (int i = 0; i < 128; i++)
          {
            Jacobi = ResidueCalculation.Jacobi(encrypted_aes_key[i].add(root),
                    MPK);

            if (Jacobi == 1)
              {
                binary_aes_key[i] = 1;
              }
            else if (Jacobi == -1)
              {
                binary_aes_key[i] = 0;
              }
            else
              {
                binary_aes_key[i] = 0; // error
                throw new DecryptException(encrypted_aes_key[i].add(SkID.
                        multiply(BigInteger.valueOf(2))).mod(MPK), SkID, MPK);
              }
          }
        return binary_aes_key;
    }

    public byte[] encryptData(String inname, String outname, BigInteger PkID,
                              BigInteger MPK, BigInteger sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
    {

        byte[] binaryKey;
        FileOutputStream fout = new FileOutputStream(outname);
        FileInputStream fin = new FileInputStream(inname);
        DataOutputStream dos = new DataOutputStream(fout);
        byte[] raw;
        BigInteger[] ciphertext;
        BigInteger[] inv_ciphertext;
        int data_size;
        byte[] data_to_encrypt;
        byte[] encrypted_data;

        Sign signature = new Sign();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey skey = kgen.generateKey();
        raw = skey.getEncoded();

        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        binaryKey = Util.KeyToBinary(raw);
        ciphertext = new BigInteger[binaryKey.length];
        inv_ciphertext = new BigInteger[binaryKey.length];
        encryptKey(binaryKey, ciphertext, inv_ciphertext, MPK, PkID);
        data_size = fin.available(); // размер шифруемых данных
        data_to_encrypt = new byte[data_size];
        fin.read(data_to_encrypt);
        encrypted_data = cipher.doFinal(data_to_encrypt);
        writeEncryptedData(dos, ciphertext, inv_ciphertext, encrypted_data);
        FileInputStream fis = new FileInputStream(outname);
        writeSignature(fis, dos, signature, MPK, sk, pk);
        dos.close();
        fout.close();
        fis.close();
        return data_to_encrypt;











    }
     public byte[] encryptData(InputStream is, BigInteger PkID,
                              BigInteger MPK, BigInteger sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
    {

        byte[] binaryKey;
       //FileOutputStream fout = new FileOutputStream(outname);
       // FileInputStream fin = new FileInputStream(inname);
        ByteArrayOutputStream out  = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(out);
        byte[] raw;
        BigInteger[] ciphertext;
        BigInteger[] inv_ciphertext;
        int data_size;
        byte[] data_to_encrypt;
        byte[] encrypted_data;
        byte[] result;

        Sign signature = new Sign();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey skey = kgen.generateKey();
        raw = skey.getEncoded();

        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        binaryKey = Util.KeyToBinary(raw);
        ciphertext = new BigInteger[binaryKey.length];
        inv_ciphertext = new BigInteger[binaryKey.length];
        encryptKey(binaryKey, ciphertext, inv_ciphertext, MPK, PkID);
        data_size = is.available(); // размер шифруемых данных
        data_to_encrypt = new byte[data_size];
        is.read(data_to_encrypt);
        encrypted_data = cipher.doFinal(data_to_encrypt);
        writeEncryptedData(dos, ciphertext, inv_ciphertext, encrypted_data);
       // FileInputStream fis = new FileInputStream(outname);
        writeSignature(is, dos, signature, MPK, sk, pk);
        result = out.toByteArray();
        dos.close();
        //fout.close();
        out.close();
        is.close();
        return result;











    }

    public byte[] decryptData(String inname, String outname, String id,
                              BigInteger SkID, BigInteger MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecryptException
    {
        boolean negative = false;
        BigInteger[] encrypted_aes_key = new BigInteger[128];
        Cryptocontainer cc = new Cryptocontainer();
        BigInteger pk = genPkID(id, MPK);
        BigInteger quadr = SkID.modPow(BigInteger.valueOf(2), MPK);
        Sign signature = new Sign();
        if (quadr.compareTo(pk) == 0)
          {
            negative = false;

          }
        else
          {
            negative = true;

          }
        FileInputStream fin = new FileInputStream(inname);
        DataInputStream ds = new DataInputStream(fin);
        cc = cc.getCryptocontainerParameters(fin, ds);
        if (cc == null)
          {
            return null;
          }
        ds.close();
        fin.close();
        fin = new FileInputStream(inname);
        ds = new DataInputStream(fin);

        byte[] data = new byte[cc.dataSize - cc.signatureSize];
        ds.read(data);

        boolean check = verifySignature(ds, signature, id, data, pkey, MPK);
        if (check == false)
          {
            return null;
          }
        fin.close();
        ds.close();
        fin = new FileInputStream(inname);
        DataInputStream din = new DataInputStream(fin);
        Util.GetEncryptedKey(din, negative, cc, encrypted_aes_key);
        int[] binary_aes_key = new int[128];
        binary_aes_key = decryptKey(encrypted_aes_key, SkID, MPK);
        byte[] raw = new byte[16];
        raw = Util.BinaryToByteKey(binary_aes_key);
        din.close();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] encrypted_data = new byte[cc.encryptedDataSize];
        System.arraycopy(data, cc.firstKeySize + cc.secondKeySize + 12,
                encrypted_data, 0, cc.encryptedDataSize);
        byte[] decrypted_data = cipher.doFinal(encrypted_data);


        FileOutputStream fos = new FileOutputStream(outname);
        fos.write(decrypted_data);
        fos.close();
        return decrypted_data;

    }
     public byte[] decryptData(InputStream is, String id,
                              BigInteger SkID, BigInteger MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecryptException
    {
        boolean negative = false;
        BigInteger[] encrypted_aes_key = new BigInteger[128];
        Cryptocontainer cc = new Cryptocontainer();
        BigInteger pk = genPkID(id, MPK);
        BigInteger quadr = SkID.modPow(BigInteger.valueOf(2), MPK);
        Sign signature = new Sign();
        if (quadr.compareTo(pk) == 0)
          {
            negative = false;

          }
        else
          {
            negative = true;

          }
        //FileInputStream fin = new FileInputStream(inname);
        DataInputStream ds = new DataInputStream(is);
        cc = cc.getCryptocontainerParameters(is, ds);
        if (cc == null)
          {
            return "Failed to decrypt: perhaps a letter was changed".getBytes();
          }
        ds.close();
        is.close();
       // fin = new FileInputStream(inname);
        ds = new DataInputStream(is);

        byte[] data = new byte[cc.dataSize - cc.signatureSize];
        ds.read(data);

        boolean check = verifySignature(ds, signature, id, data, pkey, MPK);
        if (check == false)
          {
            return "Failed to decrypt: perhaps a letter was changed (Error during signature verification)".getBytes();
          }
        is.close();
        ds.close();
     //   fin = new FileInputStream(inname);
        DataInputStream din = new DataInputStream(is);
        Util.GetEncryptedKey(din, negative, cc, encrypted_aes_key);
        int[] binary_aes_key = new int[128];
        binary_aes_key = decryptKey(encrypted_aes_key, SkID, MPK);
        byte[] raw = new byte[16];
        raw = Util.BinaryToByteKey(binary_aes_key);
        din.close();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] encrypted_data = new byte[cc.encryptedDataSize];
        System.arraycopy(data, cc.firstKeySize + cc.secondKeySize + 12,
                encrypted_data, 0, cc.encryptedDataSize);
        byte[] decrypted_data = cipher.doFinal(encrypted_data);


       // FileOutputStream fos = new FileOutputStream(outname);
       // fos.write(decrypted_data);
        //fos.close();
        return decrypted_data;

    }
}
