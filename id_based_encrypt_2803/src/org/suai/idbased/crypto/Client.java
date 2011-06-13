package org.suai.idbased.crypto;

import org.suai.idbased.util.Util;
import org.suai.idbased.util.ResidueCalculation;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Client {
    private final int aesKeyLen = 128;
    private final int intLen = java.lang.Integer.SIZE/8;

    public BigInteger genPkID(String id, BigInteger MPK) throws NoSuchAlgorithmException
    {
        BigInteger a;
        int j = 0;
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

    public void encryptKey(byte[] binaryKey, BigInteger[] ciphertext,
                            BigInteger[] invCiphertext, BigInteger MPK,
                            BigInteger PkID)
    {
        byte m = 0;
        int j = 0;
        BigInteger invT;
        BigInteger t;
        BigInteger b;
        Random rand = new Random();
        int length = MPK.bitLength() / 4;
        int keyLength = binaryKey.length;
        for (int i = 0; i < keyLength ; i++)
          {
            m = binaryKey[i];
            while (true)
              {
                t = new BigInteger(length, rand);
                j = ResidueCalculation.Jacobi(t, MPK);
                if ((m == 0 && j == -1) || (m == 1 && j == 1))
                  {
                    invT = t.modInverse(MPK);
                    b = PkID.multiply(invT);
                    ciphertext[i] = t.add(b).mod(MPK);
                    invCiphertext[i] = t.subtract(b).mod(MPK);
                    break;
                  }
              }
          }
    }

    private void writeEncryptedData(DataOutputStream dos,
                                    BigInteger[] ciphertext,
                                    BigInteger[] invCiphertext,
                                    byte[] encrypted_data) throws IOException
    {
        int keySizeFirst = 0;
        int keySizeScnd = 0;
        for (int i = 0; i < ciphertext.length; i++)
          {
            keySizeFirst = keySizeFirst + ciphertext[i].toByteArray().length;
          }
        for (int i = 0; i < invCiphertext.length; i++)
          {
            keySizeScnd = keySizeScnd + invCiphertext[i].toByteArray().length;
          }
       
        dos.writeInt(keySizeFirst + this.aesKeyLen * this.intLen);
        dos.writeInt(keySizeScnd + this.aesKeyLen * this.intLen);
       
        for (int i = 0; i < ciphertext.length; i++)
          {
            dos.writeInt(ciphertext[i].toByteArray().length);
            dos.write(ciphertext[i].toByteArray());
          }
        for (int i = 0; i < invCiphertext.length; i++)
          {
            dos.writeInt(invCiphertext[i].toByteArray().length);
            dos.write(invCiphertext[i].toByteArray());
          }
        int encrypted_data_size = encrypted_data.length;    
        dos.writeInt(encrypted_data_size);
        dos.write(encrypted_data);
       
    }

    private void writeSignature(FileInputStream fis, DataOutputStream dos,
                                Sign signature, BigInteger MPK, BigInteger sk,
                                long pk) throws IOException, NoSuchAlgorithmException
    {

        byte[] dataToHash = new byte[fis.available()];
        fis.read(dataToHash);
        BigInteger[] sign = signature.getSign(dataToHash, sk, pk, MPK);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
    }
     private void writeSignature(ByteArrayInputStream bis, DataOutputStream dos,
                                Sign signature, BigInteger MPK, BigInteger sk,
                                long pk) throws IOException, NoSuchAlgorithmException
    {

        byte[] dataToHash = new byte[bis.available()];
        bis.read(dataToHash);
        BigInteger[] sign = signature.getSign(dataToHash, sk, pk, MPK);
        dos.writeInt(sign[0].toByteArray().length);
        dos.writeInt(sign[1].toByteArray().length);
        dos.write(sign[0].toByteArray());
        dos.write(sign[1].toByteArray());
    }

    private boolean verifySignature(DataInputStream ds, Sign signature,
                                    String id, byte[] data, long pkey,
                                    BigInteger MPK) throws NoSuchAlgorithmException, IOException
    {
       
        byte[] tByte = new byte[ds.readInt()];
        byte[] sByte = new byte[ds.readInt()];
        ds.read(tByte);
        ds.read(sByte);
        BigInteger[] sign = new BigInteger[2];
        sign[0] = new BigInteger(tByte);
        sign[1] = new BigInteger(sByte);
        return signature.verifySign(data, id, sign, pkey, MPK);
       
    }

    public int[] decryptKey(BigInteger[] encryptedAESKey, BigInteger SkID,
                             BigInteger MPK, int keylength)
    {
        int[] binaryAESKey = new int[keylength];
        int Jacobi;
        BigInteger root = SkID.add(SkID).mod(MPK);
        for (int i = 0; i < keylength; i++)
          {
            BigInteger currBit = encryptedAESKey[i].add(root);
            Jacobi = ResidueCalculation.Jacobi(currBit,
                    MPK);

            if (Jacobi == 1)
              {
                binaryAESKey[i] = 1;
              }
            else
              {
                binaryAESKey[i] = 0;
              }
          }
        return binaryAESKey;
    }

    public byte[] encryptData(String inname, String outname, BigInteger PkID,
                              BigInteger MPK, BigInteger sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
    {

        FileOutputStream fout = new FileOutputStream(outname);
        FileInputStream fin = new FileInputStream(inname);
        DataOutputStream dos = new DataOutputStream(fout);
        Sign signature = new Sign();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(this.aesKeyLen);
        SecretKey skey = kgen.generateKey();
        byte [] raw = skey.getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] binaryKey = Util.KeyToBinary(raw);
        BigInteger [] ciphertext = new BigInteger[binaryKey.length];
        BigInteger [] invCiphertext = new BigInteger[binaryKey.length];
        encryptKey(binaryKey, ciphertext, invCiphertext, MPK, PkID);
        byte[] dataToEncrypt = new byte[fin.available()];
        fin.read(dataToEncrypt);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);
        writeEncryptedData(dos, ciphertext, invCiphertext, encryptedData);
        FileInputStream fis = new FileInputStream(outname);
        writeSignature(fis, dos, signature, MPK, sk, pk);
        dos.close();
        fout.close();
        fis.close();
        return dataToEncrypt;
    }
     public byte[] encryptData(ByteArrayInputStream is, BigInteger PkID,
                              BigInteger MPK, BigInteger sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException
    {
        ByteArrayOutputStream out  = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(out);
        Sign signature = new Sign();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(this.aesKeyLen);
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] binaryKey = Util.KeyToBinary(raw);
        BigInteger[] ciphertext = new BigInteger[binaryKey.length];
        BigInteger[] invCiphertext = new BigInteger[binaryKey.length];
        encryptKey(binaryKey, ciphertext, invCiphertext, MPK, PkID);
        byte[] dataToEncrypt = new byte[is.available()];
        is.read(dataToEncrypt);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);
        writeEncryptedData(dos, ciphertext, invCiphertext, encryptedData);
        ByteArrayInputStream bis = new ByteArrayInputStream (out.toByteArray());
        writeSignature(bis, dos, signature, MPK, sk, pk);
        byte [] result = out.toByteArray();
        dos.close();
        out.close();
        is.close();
        return result;
    }

    public byte[] decryptData(String inname, String outname, String id,
                              BigInteger SkID, BigInteger MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        boolean negative = false;
        BigInteger[] encryptedAESKey = new BigInteger[this.aesKeyLen];
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
        cc = cc.getCryptocontainerParameters(ds);
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
        Util.GetEncryptedKey(din, negative, cc, encryptedAESKey);
        int[] binaryAESKey = decryptKey(encryptedAESKey, SkID, MPK, this.aesKeyLen);
        byte[] raw  = Util.BinaryToByteKey(binaryAESKey);
        din.close();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] encryptedData = new byte[cc.encryptedDataSize];
        System.arraycopy(data, cc.firstKeySize + cc.secondKeySize + 12,
                encryptedData, 0, cc.encryptedDataSize);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        FileOutputStream fos = new FileOutputStream(outname);
        fos.write(decryptedData);
        fos.close();
        return decryptedData;

    }
     public byte[] decryptData(ByteArrayInputStream is, String id, String idfrom,
                              BigInteger SkID, BigInteger MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        
        boolean negative = false;
        BigInteger[] encryptedAESKey = new BigInteger[128];
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
        DataInputStream ds = new DataInputStream(is);
        cc = cc.getCryptocontainerParameters(ds);
        if (cc == null)
          {
            return "[IBC JAMES MAILET]: Failed to decrypt: letter was changed (Cryptocontainer is damaged)".getBytes();
          }
        ds.close();
        is.reset();
        ds = null;
        ds = new DataInputStream(is);
        byte[] data = new byte[cc.dataSize - cc.signatureSize];
        ds.read(data);
        boolean check = verifySignature(ds, signature, idfrom, data, pkey, MPK);
        if (check == false)
          {
            return "[IBC JAMES MAILET]: Failed to decrypt: maybe a letter was changed (Error during signature verification)".getBytes();
          }
        is.reset();
        ds.close();
        DataInputStream din = new DataInputStream(is);
        Util.GetEncryptedKey(din, negative, cc, encryptedAESKey);
        int[] binaryAESKey = decryptKey(encryptedAESKey, SkID, MPK, this.aesKeyLen);
        byte[] raw = Util.BinaryToByteKey(binaryAESKey);
        din.close();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] encryptedData = new byte[cc.encryptedDataSize];
        System.arraycopy(data, cc.firstKeySize + cc.secondKeySize + 12,
                encryptedData, 0, cc.encryptedDataSize);
        return cipher.doFinal(encryptedData);
    }
}
