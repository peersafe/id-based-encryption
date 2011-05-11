/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.idbased;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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

/**
 *
 * @author foxneig
 */
public class KeyStorage {
    private String storage;
    private String pass;
    private ArrayList <Domain> domains = new ArrayList();
    private ArrayList <String> domainNames = new ArrayList();


    public KeyStorage (String path) {
        this.storage = path;
        try {
            this.load();
        } catch (FileNotFoundException ex) {
            System.out.println ("Storage not found");
            return;
        }
    }
    public void addKey (String id, byte [] mpk, byte [] msk1, byte [] msk2, String password) throws FileNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
       this.load();
       if (this.domainNames.contains(id)) {
           System.out.println ("Domain already exist, to change keys please remove old keydata");
           return;
        }

       FileWriter pw = new FileWriter (storage, true);
       BASE64Encoder enc = new BASE64Encoder();
       MessageDigest MD = MessageDigest.getInstance("MD5");

       MD.update(password.getBytes());
       byte[] key = MD.digest();
       MD.reset();
       MD.update(mpk);
       byte[] crc_mpk = MD.digest();
       MD.reset();
       MD.update(msk1);
       byte[] crc_msk1 = MD.digest();
       MD.reset();
       MD.update(msk2);
       byte[] crc_msk2 = MD.digest();

       SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
       Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
       cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
       byte[] encr_msk1 = cipher.doFinal(msk1);
       byte[] encr_msk2= cipher.doFinal(msk2);
       String mpk_b64 = enc.encode(mpk);
       String msk1_b64 = enc.encode(encr_msk1);
       String msk2_b64 = enc.encode(encr_msk2);
       String crc_mpk_b64 = enc.encode(crc_mpk);
       String crc_msk1_b64 = enc.encode(crc_msk1);
       String crc_msk2_b64 = enc.encode(crc_msk2);



       pw.append("<Domain>"+"\n");

       pw.append("<Name>"+id+"<Name>");
       pw.append("<MPK>"+ mpk_b64+ "<MPK>"+"\n");
       pw.append ("<MSK1>"+ msk1_b64+ "<MSK1>"+"\n");
       pw.append ("<MSK1Checksum>"+crc_msk1_b64+ "<MSK1Checksum"+">" + "\n");
       pw.append ("<MSK2>"+msk2_b64 + "<MSK2>"+"\n");
       pw.append ("<MSK2Checksum>"+crc_msk2_b64+"<MSK2Checksum"+">"+"\n");

       pw.append ("<Domain>"+"\n");



       pw.close();








    }
    public void delKey (String id, String password) throws IOException {
        this.load();
        byte [] mpk = new byte [128];
        byte [] msk1 = new byte [128];
        byte [] msk2 = new byte [128];
        int res = 0;
        try {
           res =  this.getKey(id, mpk, msk1, msk2, password);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (res == 1) {
            // password correct, start deleting key
             File inFile = new File(storage);
             if (!inFile.isFile()) {
                System.out.println("Keystorage is not exist");
                return;
      }
             Domain delDomain = this.findDomain(id);
             for (int i = 0; i < this.domains.size(); i++) {
                 if (this.domains.get(i).equals(delDomain)) {
                     this.domains.remove(i);
                     this.domains.remove(i);
                     break;
                 }
                 System.out.println ("Domain deleted");
             }

             File tempFile = new File(inFile.getAbsolutePath() + ".tmp");
             PrintWriter pw = new PrintWriter(new FileWriter(tempFile),true);

             for (int i = 0; i < this.domains.size(); i++) {

                  pw.append("<Domain>"+"\n");
                  pw.append("<Name>"+this.domains.get(i).getName()+"<Name>");
                  pw.append("<MPK>"+this.domains.get(i).getMPK()+"<MPK>"+"\n");
                  pw.append ("<MSK1>"+this.domains.get(i).getMSK1()+ "<MSK1>"+"\n");
                  pw.append ("<MSK1Checksum>"+this.domains.get(i).getMSK1CheckSum()+"<MSK1Checksum"+">" + "\n");
                  pw.append ("<MSK2>"+this.domains.get(i).getMSK2()+"<MSK2>"+"\n");
                  pw.append ("<MSK2Checksum>"+this.domains.get(i).getMSK2CheckSum()+"<MSK2Checksum"+">"+"\n");
                  pw.append ("<Domain>"+"\n");
             }
             pw.close();
             //delete old file
             if (!inFile.delete()) {
             System.out.println("Could not delete file");
             return;
      }
             //rename new file
               if (!tempFile.renameTo(inFile))
                 System.out.println("Could not rename file");
             System.out.println ("Domain deleted");







        }
        else
            System.out.println ("Password incorrect, key not deleted");


    }
    private Domain findDomain (String id) {

        for (int i = 0; i < domains.size(); i++) {
            if (domains.get(i).getName().equals(id))
                return domains.get(i);
        }
        return null;

    }
    public int getKey (String id, byte [] mpk, byte [] msk1, byte [] msk2, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException {
        this.load();
        Domain currDomain;
        String smpk_b64;
        String encr_msk1_b64;
        String encr_msk2_b64;
        String msk1_checksum_b64;
        String msk2_checksum_b64;
        byte [] decr_msk1 = null;
        byte [] decr_msk2 = null;
        if (this.domainNames.contains(id) == false) {
            System.out.println ("Domain not found");
            mpk = null;
            msk1 = null;
            msk2 = null;
            return -1;
        }
        else {
            currDomain = this.findDomain(id);
            // get Domain Param
            smpk_b64 = currDomain.getMPK();
            encr_msk1_b64 = currDomain.getMSK1();
            encr_msk2_b64 = currDomain.getMSK2();
            msk1_checksum_b64 = currDomain.getMSK1CheckSum();
            msk2_checksum_b64 = currDomain.getMSK2CheckSum();
            BASE64Decoder dec = new BASE64Decoder();
            // get AES key from pass
            MessageDigest MD = MessageDigest.getInstance("MD5");
            MD.update(password.getBytes());
            byte[] key = MD.digest();
            MD.reset();
            // Decode encrypted data from Base64
            mpk = dec.decodeBuffer(smpk_b64);
            byte [] crc1 = dec.decodeBuffer(msk1_checksum_b64);
            byte [] crc2 = dec.decodeBuffer(msk2_checksum_b64);
            byte [] encr_msk1 = dec.decodeBuffer(encr_msk1_b64);
            byte [] encr_msk2 = dec.decodeBuffer(encr_msk2_b64);
            //Starting decrypting

            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            try {
                decr_msk1 = cipher.doFinal(encr_msk1);
            } catch (BadPaddingException ex) {
                System.out.println ("Password incorrect");
                mpk = null;
                msk1 = null;
                msk2 = null;
                return -1;
            }
            try {
                decr_msk2 = cipher.doFinal(encr_msk2);
            } catch (BadPaddingException ex) {
                System.out.println ("Password incorrect");
                mpk = null;
                msk1 = null;
                msk2 = null;
                return -1;
            }
            //Checking correctivity
            MD.update(decr_msk1);
            byte []crc_1 = MD.digest();
            MD.reset();
            MD.update(decr_msk2);
            byte []crc_2 = MD.digest();
            if (Arrays.equals(crc1, crc_1) == true && Arrays.equals(crc2, crc_2) == true) {
                System.out.println ("Password correct");
                msk1 = decr_msk1;
                msk2 = decr_msk2;
                return 1;
            }
            else {
                System.out.println ("Password incorrect");
                mpk = null;
                msk1 = null;
                msk2 = null;
                return -1;
            }







        }



    }





  private void load () throws FileNotFoundException {
   FileInputStream fis = new FileInputStream (storage);
   ArrayList <String> list = new ArrayList();
   String dn;
   String mpk;
   String msk1;
   String msk2;
   String msk1checksum;
   String msk2checksum;
   StringBuilder sb = new StringBuilder ();
   Scanner scanner  = new Scanner (fis);
   scanner.useDelimiter("<Domain>");
   while (scanner.hasNext()) {
  list.add(scanner.next().replaceAll("\n", ""));
  }
 scanner = null;
 for (int i = 0; i < list.size(); i++) {
     if (list.get(i).equals("")) continue;
  scanner = new Scanner (list.get(i));
  Domain currDomain = new Domain ();
  scanner.findInLine("<Name>(\\p{ASCII}+)<Name><MPK>(\\p{ASCII}+)<MPK><MSK1>(\\p{ASCII}+)<MSK1><MSK1Checksum>(\\p{ASCII}+)<MSK1Checksum><MSK2>(\\p{ASCII}+)<MSK2><MSK2Checksum>(\\p{ASCII}+)<MSK2Checksum>");
  MatchResult result = scanner.match();
  if (result.groupCount() == 0) {
      System.out.println ("Error by loading keydata from keystorage.");
      return;
  }
  else {
  dn = result.group(1);
  mpk = result.group(2);
  msk1 = result.group(3);
  msk1checksum = result.group(4);
  msk2 = result.group(5);
  msk2checksum = result.group(6);
  currDomain.set(dn, mpk, msk1, msk2, msk1checksum, msk2checksum);
  domains.add(currDomain);
  scanner = null;
  currDomain = null;
        }
        }
 
  for (int i = 0; i < this.domains.size(); i++) {
            this.domainNames.add(this.domains.get(i).getName());
        }
      


    }
    public static void main (String [] args) throws FileNotFoundException {
        KeyStorage ks = new KeyStorage ("/home/foxneig/keystorage.ks");
        Random rand = new Random ();
        byte [] mpk = new byte [128];
        byte [] msk1 = new byte [128];
        byte [] msk2 = new byte [128];

        rand.nextBytes(mpk);
        rand.nextBytes(msk1);
        rand.nextBytes(msk2);
        
        try {
      ks.addKey("mail.ru", mpk, msk1, msk2, "root");
        } catch (IOException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
        ks.addKey("mail.ru", mpk, msk1, msk2, "root");
        } catch (IOException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        }

       
        try {
            ks.getKey("domain.com", mpk, msk1, msk2, "password");
            ks.getKey("anotherdomain.com", mpk, msk1, msk2, "123214");
            ks.getKey("gmail.com", mpk, msk1, msk2, "root");
            ks.getKey("mail.ru", mpk, msk1, msk2, "root");

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        }
            try {
                ks.getKey("domain.com", mpk, msk1, msk2, "password123");
                ks.getKey("anotherdomain.com", mpk, msk1, msk2, "1232142321");
                ks.getKey("gmail.com", mpk, msk1, msk2, "toor");
                ks.getKey("mail.ru", mpk, msk1, msk2, "toor");
                ks.getKey("gmail.org", mpk, msk1, msk2, "root");
                ks.getKey("notfound.com", mpk, msk1, msk2, "root");

            } catch (NoSuchAlgorithmException ex1) {
                Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (NoSuchPaddingException ex1) {
                Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (InvalidKeyException ex1) {
                Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (IOException ex1) {
                Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (IllegalBlockSizeException ex1) {
                Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex1);
            }
        try {
            ks.delKey("gmail.com", "password");
        } catch (IOException ex) {
            Logger.getLogger(KeyStorage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
    




