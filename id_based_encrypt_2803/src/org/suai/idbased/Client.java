package org.suai.idbased;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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

    public byte[] encrypt(String inname, String outname, BigInteger PkID, BigInteger MPK, BigInteger sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

        StringBuffer sb = new StringBuffer();
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
        sb = Util.KeyToBinary(raw);
        ciphertext = new BigInteger[sb.length()];
        inv_ciphertext = new BigInteger[sb.length()];
        Util.EncryptKey(sb, ciphertext, inv_ciphertext, MPK, PkID);
        data_size = fin.available(); // размер шифруемых данных
        data_to_encrypt = new byte[data_size];
        fin.read(data_to_encrypt);
        encrypted_data = cipher.doFinal(data_to_encrypt);
        Util.WriteEncryptedData(dos, ciphertext, inv_ciphertext, encrypted_data);
        FileInputStream fis = new FileInputStream(outname);
        Util.WriteSignature(fis, dos, signature, MPK, sk, pk);
        dos.close();
        fout.close();
        fis.close();
        return data_to_encrypt;











    }

    public byte[] decrypt(String inname, String outname, String id, BigInteger SkID, BigInteger MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecryptException {
        boolean negative = false;
        BigInteger[] encrypted_aes_key = new BigInteger[128];
        BigInteger pk = Util.genPkID(id, MPK);
        BigInteger quadr = SkID.modPow(BigInteger.valueOf(2), MPK);
        Sign signature = new Sign();
        if (quadr.compareTo(pk) == 0) {
            negative = false;

        } else {
            negative = true;

        }
        FileInputStream fin = new FileInputStream(inname);
        DataInputStream ds = new DataInputStream(fin);
        Cryptocontainer cc = Util.GetCryptocontainerParameters(fin, ds);
        if (cc == null) {
            return null;
        }
        ds.close();
        fin.close();
        fin = new FileInputStream(inname);
        ds = new DataInputStream(fin);

        byte[] data = new byte[cc.dataSize - cc.signatureSize];
        ds.read(data);

        Object check = Util.ReadSignature(ds, signature, id, data, pkey, MPK);
        if (check == null) {
            return null;
        }
        fin.close();
        ds.close();
        fin = new FileInputStream(inname);
        DataInputStream din = new DataInputStream(fin);
        Util.GetEncryptedKey(din, negative, cc, encrypted_aes_key);
        int[] binary_aes_key = new int[128];
        binary_aes_key = Util.DecryptKey(encrypted_aes_key, SkID, MPK);
        byte[] raw = new byte[16];
        raw = Util.BinaryToByteKey(binary_aes_key);
        din.close();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] encrypted_data = new byte[cc.encryptedDataSize];
        System.arraycopy(data, cc.firstKeySize + cc.secondKeySize + 12, encrypted_data, 0, cc.encryptedDataSize);
        byte[] decrypted_data = cipher.doFinal(encrypted_data);


        FileOutputStream fos = new FileOutputStream(outname);
        fos.write(decrypted_data);
        fos.close();
        return decrypted_data;

    }

    public static void main_(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, DecryptException {
        PKG pkg = new PKG(512);
        String id = "foxneig@gmail.com";
        pkg.setup();
        pkg.keyExtract(id);
        pkg.getSecretExponent();
        BigInteger PkID = Util.genPkID(id, pkg.MPK);
        Client client = new Client();
        BigInteger skey = pkg.signKeyExtract("foxneig@gmail.com");
        byte[] data_to_encrypt = client.encrypt("1.pdf", "out.dat", PkID, pkg.MPK, skey, pkg.e);
        byte[] decr_data = client.decrypt("out.dat", "decr", "foxneig@gmail.com", pkg.MSK, pkg.MPK, pkg.e);
        System.out.println("Decrypt: " + Arrays.equals(data_to_encrypt, decr_data));






    }
}
