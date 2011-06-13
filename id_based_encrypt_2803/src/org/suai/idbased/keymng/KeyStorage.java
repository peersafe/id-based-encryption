
package org.suai.idbased.keymng;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.MatchResult;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class KeyStorage {


    private String storage;
    private ArrayList<Domain> domains = new ArrayList();
    private ArrayList<String> domainNames = new ArrayList();

    public class Domain {
    private String domainName;
    private String MPK;
    private String MSK1;
    private String MSK2;
    private String checksumm1;
    private String checksumm2;

    public void set (String dn, String MPK, String MSK1, String MSK2, String checksumm1, String checksumm2) {
        this.domainName = dn;
        this.MPK = MPK;
        this.MSK1 = MSK1;
        this.MSK2 = MSK2;
        this.checksumm1 = checksumm1;
        this.checksumm2 = checksumm2;
    }
    public String getMPK () {
        return this.MPK;
    }
    public String getMSK1 () {
        return this.MSK1;
    }
    public String getMSK2 () {
        return this.MSK2;
    }
    public String getName () {
        return this.domainName;
    }
    public String getMSK1CheckSum () {
        return this.checksumm1;
    }
      public String getMSK2CheckSum () {
        return this.checksumm2;
    }

}

    public KeyStorage(String path) throws FileNotFoundException
    {
        this.storage = path;
        this.load();

    }

    public void addKey(String id, byte[] mpk, byte[] msk1, byte[] msk2,
                       String password) throws FileNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        this.load();
        if (this.domainNames.contains(id))
          {
            System.out.println(
                    "[KEYSTORAGE]: Domain " + id +" already exist, to change keys please remove old keydata");
            return;
          }

        FileWriter pw = new FileWriter(storage, true);
        BASE64Encoder enc = new BASE64Encoder();
        MessageDigest MD = MessageDigest.getInstance("MD5");
        MD.update(password.getBytes());
        byte[] key = MD.digest();
        MD.reset();
        MD.update(msk1);
        MD.update(key);
        byte[] chSumMsk1 = MD.digest();
        MD.reset();
        MD.update(msk2);
        MD.update(key);
        byte[] chSumMsk2 = MD.digest();
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encr_msk1 = cipher.doFinal(msk1);
        byte[] encr_msk2 = cipher.doFinal(msk2);
        pw.append("<Domain>" + "\n");
        pw.append("<Name>" + id + "<Name>" +"\n");
        pw.append("<MPK>" + enc.encode(mpk) + "<MPK>" + "\n");
        pw.append("<MSK1>" + enc.encode(encr_msk1) + "<MSK1>" + "\n");
        pw.append("<MSK1Checksum>" + enc.encode(chSumMsk1) + "<MSK1Checksum>" + "\n");
        pw.append("<MSK2>" + enc.encode(encr_msk2) + "<MSK2>" + "\n");
        pw.append("<MSK2Checksum>" + enc.encode(chSumMsk2) + "<MSK2Checksum>" + "\n");
        pw.append("<Domain>" + "\n");
        pw.close();
    }

    public void delKey(String id, String password) throws IOException
    {
        this.load();
        BigInteger[] keys = new BigInteger[3];
        int res = 0;
        try
          {
            res = this.getKey(id, keys, password);
          }
        catch (NoSuchAlgorithmException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (InvalidKeyException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IOException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IllegalBlockSizeException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        if (res == 1)
          {
            File inFile = new File(storage);
            if (!inFile.isFile())
              {
                System.out.println("[KEYSTORAGE]: Keystorage is not exist");
                return;
              }
            Domain delDomain = this.findDomain(id);
            for (int i = 0; i < this.domains.size(); i++)
              {
                if (this.domains.get(i).equals(delDomain))
                  {
                    this.domains.remove(i);
                    this.domainNames.remove(i);
                  }
              }
            File tempFile = new File(inFile.getAbsolutePath() + ".tmp");
            PrintWriter pw = new PrintWriter(new FileWriter(tempFile), true);
            for (int i = 0; i < this.domains.size(); i++)
              {
                pw.append("<Domain>" + "\n");
                pw.append("<Name>" + this.domains.get(i).getName() + "<Name>" +"\n");
                pw.append(
                        "<MPK>" + this.domains.get(i).getMPK() + "<MPK>" + "\n");
                pw.append(
                        "<MSK1>" + this.domains.get(i).getMSK1() + "<MSK1>" + "\n");
                pw.append(
                        "<MSK1Checksum>" + this.domains.get(i).getMSK1CheckSum() + "<MSK1Checksum" + ">" + "\n");
                pw.append(
                        "<MSK2>" + this.domains.get(i).getMSK2() + "<MSK2>" + "\n");
                pw.append(
                        "<MSK2Checksum>" + this.domains.get(i).getMSK2CheckSum() + "<MSK2Checksum" + ">" + "\n");
                pw.append("<Domain>" + "\n");
              }
            pw.close();
            if (!inFile.delete())
              {
                System.out.println("[KEYSTORAGE]: File " + inFile.getName() +"locked");
                return;
              }
            if (!tempFile.renameTo(inFile))
              {
               System.out.println("[KEYSTORAGE]: File " + inFile.getName() +"locked");
               return;
              }
            System.out.println("[KEYSTORAGE]: Domain " + id + " has been deleted");
          }
        else
          {
            System.out.println("[KEYSTORAGE]: Password incorrect, domain " + id + " not deleted");
          }
    }

    private Domain findDomain(String id)
    {

        for (int i = 0; i < domains.size(); i++)
          {
            if (domains.get(i).getName().equals(id))
              {
                return domains.get(i);
              }
          }
        return null;

    }

    public int getKey(String id, BigInteger[] keys, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException
    {
        this.load();
        Domain currDomain;
        String MPKBase64;
        String encryptedMSK1BASE64;
        String encryptedMSK2BASE64;
        String checksumMSK1BASE64;
        String checksumMSK2BASE64;
        byte[] decryptedMSK1 = null;
        byte[] decryptedMSK2 = null;
        if (this.domainNames.contains(id) == false)
          {
            System.out.println("[KEYSTORAGE]: Domain " +id+ " not found in "+this.storage);
            return -1;
          }
        else
          {
            currDomain = this.findDomain(id);          
            MPKBase64 = currDomain.getMPK();
            encryptedMSK1BASE64 = currDomain.getMSK1();
            encryptedMSK2BASE64 = currDomain.getMSK2();
            checksumMSK1BASE64 = currDomain.getMSK1CheckSum();
            checksumMSK2BASE64 = currDomain.getMSK2CheckSum();
            BASE64Decoder dec = new BASE64Decoder();
            MessageDigest MD = MessageDigest.getInstance("MD5");
            MD.update(password.getBytes());
            byte[] key = MD.digest();
            MD.reset();
            byte[] crc1 = dec.decodeBuffer(checksumMSK1BASE64);
            byte[] crc2 = dec.decodeBuffer(checksumMSK2BASE64);
            byte[] encryptedMSK1 = dec.decodeBuffer(encryptedMSK1BASE64);
            byte[] encryptedMSK2 = dec.decodeBuffer(encryptedMSK2BASE64);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            try
              {
                decryptedMSK1 = cipher.doFinal(encryptedMSK1);
              }
            catch (BadPaddingException ex)
              {
                System.out.println("[KEYSTORAGE]: Password incorrect, keys for " +id+" not loaded");
                return -1;
              }
            try
              {
                decryptedMSK2 = cipher.doFinal(encryptedMSK2);
              }
            catch (BadPaddingException ex)
              {
                System.out.println("[KEYSTORAGE]: Password incorrect, keys for " +id+" not loaded");
                return -1;
              }
            MD.update(decryptedMSK1);
            MD.update(key);
            byte[] crc_1 = MD.digest();
            MD.reset();
            MD.update(decryptedMSK2);
            MD.update(key);
            byte[] crc_2 = MD.digest();
            if (Arrays.equals(crc1, crc_1) == true && Arrays.equals(crc2, crc_2) == true)
              {
                keys[0] = new BigInteger(dec.decodeBuffer(MPKBase64));
                keys[1] = new BigInteger(decryptedMSK1);
                keys[2] = new BigInteger(decryptedMSK2);
                return 1;
              }
            else
              {
                System.out.println("[KEYSTORAGE]: Password incorrect, keys for "+id+"not loaded");
                return -1;
              }
          }
    }

    private void load() throws FileNotFoundException
    {

        FileInputStream fis = new FileInputStream(storage);
        ArrayList<String> list = new ArrayList();
        String regExp = "<Name>(\\p{ASCII}+)<Name><MPK>(\\p{ASCII}+)<MPK><MSK1>(\\p{ASCII}+)<MSK1><MSK1Checksum>(\\p{ASCII}+)<MSK1Checksum><MSK2>(\\p{ASCII}+)<MSK2><MSK2Checksum>(\\p{ASCII}+)<MSK2Checksum>";
        String dn;
        String mpk;
        String msk1;
        String msk2;
        String msk1checksum;
        String msk2checksum;
        Scanner scanner = new Scanner(fis);
        scanner.useDelimiter("<Domain>");
        while (scanner.hasNext())
          {
            list.add(scanner.next().replaceAll("\n", ""));
          }
        scanner = null;
        for (int i = 0; i < list.size(); i++)
          {
            if (list.get(i).equals(""))
              {
                continue;
              }
            scanner = new Scanner(list.get(i));
            scanner.findInLine(regExp);
            MatchResult result = scanner.match();
            if (result.groupCount() == 0)
              {
                System.out.println("[KEYSTORAGE]: Error by loading keydata from keystorage.");
                return;
              }
            else
              {
                dn = result.group(1);
                mpk = result.group(2);
                msk1 = result.group(3);
                msk1checksum = result.group(4);
                msk2 = result.group(5);
                msk2checksum = result.group(6);

                if (this.domainNames.contains(dn))
                  {
                    continue;
                  }
                else
                  {
                    Domain currDomain = new Domain();
                    currDomain.set(dn, mpk, msk1, msk2, msk1checksum,
                            msk2checksum);
                    domains.add(currDomain);
                    domainNames.add(dn);
                    currDomain = null;
                  }
              }
            scanner = null;
          }
    }

    public static void main (String[] args) throws FileNotFoundException
    {
        KeyStorage ks = new KeyStorage("/home/foxneig/keystorage.ks");
        System.out.println (java.lang.Integer.SIZE);
        Random rand = new Random();
        byte[] mpk = new byte[128];
        byte[] msk1 = new byte[128];
        byte[] msk2 = new byte[128];
        BigInteger[] keys = new BigInteger[3];

        rand.nextBytes(mpk);
        rand.nextBytes(msk1);
        rand.nextBytes(msk2);

        try
          {
            ks.addKey("mail.ru", mpk, msk1, msk2, "root");
            ks.addKey("gmail.ru", mpk, msk1, msk2, "root");
            ks.addKey("gmail.com.ru", mpk, msk1, msk2, "root");
          }
        catch (IOException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (InvalidKeyException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchAlgorithmException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IllegalBlockSizeException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (BadPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        try
          {
            ks.addKey("mail.ru", mpk, msk1, msk2, "root");
          }
        catch (IOException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (InvalidKeyException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchAlgorithmException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IllegalBlockSizeException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (BadPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }


        try
          {
            ks.getKey("domain.com", keys, "password");
            ks.getKey("anotherdomain.com", keys, "123214");
            ks.getKey("gmail.com", keys, "root");
            ks.getKey("mail.ru", keys, "root");

          }
        catch (NoSuchAlgorithmException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (NoSuchPaddingException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (InvalidKeyException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IOException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        catch (IllegalBlockSizeException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
        try
          {
            ks.getKey("domain.com", keys, "password123");
            ks.getKey("anotherdomain.com", keys, "1232142321");
            ks.getKey("gmail.com", keys, "toor");
            ks.getKey("mail.ru", keys, "toor");
            ks.getKey("gmail.org", keys, "root");
            ks.getKey("notfound.com", keys, "root");

          }
        catch (NoSuchAlgorithmException ex1)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex1);
          }
        catch (NoSuchPaddingException ex1)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex1);
          }
        catch (InvalidKeyException ex1)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex1);
          }
        catch (IOException ex1)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex1);
          }
        catch (IllegalBlockSizeException ex1)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex1);
          }
        try
          {
            ks.delKey("mail.ru", "password");
            ks.delKey("mail.ru", "root");
          }
        catch (IOException ex)
          {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null,
                    ex);
          }
    }
}
