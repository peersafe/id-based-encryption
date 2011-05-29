/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.idbased;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author foxneig
 */
public class Exp {
    private float threshold;
    private int minExpNum;
    private int maxExpNum;
    private int expNum;
    private float lastAvg;
    private float lastDisp;
    private ArrayList <Float> times = new ArrayList ();
    private float lastVar;
    public enum status {
        NotReady, ReadyVar, ReadyMaxExp;
    }
    public Exp (int min, int max, float thr) {
        this.minExpNum = min;
        this.maxExpNum = max;
        this.threshold = thr;
    }



    public void addVal (float t) {
       this.times.add(t);
    }
    public float getAvg () {
        float avg = 0;
        for (int i = 0; i < times.size(); i++) {
            avg = avg + times.get(i);
        }
        avg = avg / times.size();
        lastAvg = avg;
        return avg;
    }
    public float getDisp () {
        // D = M[x2] - M2[X]
        float sum = 0;
        float disp = 0;
        for (int i = 0; i < times.size(); i++) {
            sum = sum + (times.get(i) - this.lastAvg) * (times.get(i) - this.lastAvg);

        }
        disp = sum / times.size();
        lastDisp = disp;
        return disp;



    }
    public float getVariation () {
        this.lastVar = (float) (Math.sqrt(lastDisp) / lastAvg);
        return this.lastVar;
    }

    public status isReady () {
        expNum ++;
        if (expNum <= minExpNum) return status.NotReady;
        float avg = getAvg ();
        float disp = getDisp();
        float var = getVariation();
        if (Math.floor(var) <= threshold) return status.ReadyVar;
        if (expNum >= maxExpNum) return status.ReadyMaxExp;
        return status.NotReady;
   


    }
        public static void main (String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, DecryptException {
        /* Init IDbasedEncryption */

        PKG pkg = new PKG(512);
        pkg.setup();
        BigInteger PkID = pkg.genPkID("user@example.com", pkg.getMSK1(), pkg.getMSK2(), pkg.getMPK());
        BigInteger SkID = pkg.keyExtract("user@example.com");
        Random rand = new Random ();
        Client client = new Client();
        FileWriter out1 = new FileWriter ("/home/foxneig/ExpResult/IBE_times.txt", true);
        FileWriter out2 = new FileWriter ("/home/foxneig/ExpResult/RSA_times.txt", true);
        FileWriter out3 = new FileWriter ("/home/foxneig/ExpResult/IBE_ciphlength.txt", true);
        FileWriter out4 = new FileWriter ("/home/foxneig/ExpResult/RSA_ciphlength.txt",true);
        FileWriter out5 = new FileWriter ("/home/foxneig/ExpResult/IBE_decrypt_times.txt",true);
        FileWriter out6 = new FileWriter ("/home/foxneig/ExpResult/RSA_decrypt_times.txt",true);
         /*Init RSA Encryption */
         Cipher cipher = Cipher.getInstance("RSA");
         Cipher decipher = Cipher.getInstance("RSA");

         KeyPairGenerator Kgen = KeyPairGenerator.getInstance("RSA");
         Kgen.initialize(1024);
         KeyPair kpair = Kgen.generateKeyPair();
         cipher.init(Cipher.ENCRYPT_MODE, kpair.getPublic());
         decipher.init (Cipher.DECRYPT_MODE, kpair.getPrivate());
         byte[] doFinal = null;

         int keyLength = 0;
         int l = 0, numExp = 0;
        out1.write ("#Keylength, bit\tAverage speed, ms \n");
        out2.write ("#Keylength, bit\tAverage speed, ms \n");
        out3.write ("#Keylength, bit\tCiphertextLength, bytes \n");
        out4.write ("#Keylength, bit\tCiphertextLength, bytes \n");
        out5.write ("#Keylength, bit\tAverage speed, ms \n");
        out6.write ("#Keylength, bit\tAverage speed, ms \n");
        

        System.out.println ("Encrypt Speed Test starting");

        for (keyLength = 64; keyLength <= 512; keyLength = keyLength*2) {
        System.out.println ("KeyLength = " + keyLength);
        byte [] raw = new byte [keyLength/8];
        rand.nextBytes(raw);
        byte[] binaryKey = Util.KeyToBinary(raw);
        BigInteger[] ciphertext = new BigInteger [binaryKey.length];
        BigInteger[] inv_ciphertext = new BigInteger [binaryKey.length];
      //  Exp experimentIBE = new Exp (2000, 20000, (float) 0.15);
       // Exp experimentRSA = new Exp (2000, 100000, (float) 0.15);
        Exp experimentIBEDecr = new Exp (2000, 20000, (float) 0.15);
       // Exp experimentRSADecr = new Exp (2000, 100000, (float) 0.15);
      
       



//        while (experimentIBE.isReady()!=status.ReadyVar && experimentIBE.isReady()!=status.ReadyMaxExp) {
//            numExp++;
//
//            long start = System.currentTimeMillis();
//            client.encryptKey(binaryKey, ciphertext , inv_ciphertext, pkg.getMPK(), PkID);
//            long end = System.currentTimeMillis();
//            experimentIBE.addVal(end - start);
//            for (int i = 0; i < ciphertext.length; i++) {
//            l = l + ciphertext[i].toByteArray().length + inv_ciphertext[i].toByteArray().length;
//         }
//
//        }
//        float avg = experimentIBE.getAvg();
//
//        if (experimentIBE.isReady() == status.ReadyMaxExp) {
//            out1.write("#var = " + experimentIBE.lastVar +"\n");
//            out1.write(keyLength+"\t"+avg+"*\n");
//            out3.write (keyLength+"\t"+l/numExp+"\n");
//            System.out.println (keyLength+"\t"+l/numExp);
//            System.out.println (keyLength+"\t"+avg +"*\n");
//            }
//        else {
//            out1.write(keyLength+"\t"+avg+"\n");
//            out3.write (keyLength+"\t"+l/numExp+"\n");
//            System.out.println (keyLength+"\t"+avg);
//            System.out.println (keyLength+"\t"+l/numExp);
//            }
//        l = 0; numExp = 0;
//
//        while (experimentRSA.isReady()!=status.ReadyVar && experimentRSA.isReady()!=status.ReadyMaxExp) {
//            numExp++;
//            long start = System.currentTimeMillis();
//            doFinal = cipher.doFinal(raw);
//            long end = System.currentTimeMillis();
//            experimentRSA.addVal(end - start);
//            l += doFinal.length;
//
//
//        }
//        avg = experimentRSA.getAvg();
//        if (experimentRSA.isReady() == status.ReadyMaxExp) {
//             out2.write("#var = " + experimentRSA.lastVar +"\n");
//             out2.write(keyLength+"\t"+avg+"*\n");
//             out4.write(keyLength+"\t"+l/numExp +"\n");
//             System.out.println (keyLength+"\t"+avg +"*\n");
//             System.out.println (keyLength+"\t"+l/numExp);
//            }
//        else {
//             out2.write(keyLength+"\t"+avg+"\n");
//             out4.write(keyLength+"\t"+l/numExp);
//             System.out.println (keyLength+"\t"+avg);
//             System.out.println (keyLength+"\t"+l/numExp);
//            }
//        l = 0; numExp = 0;

        System.out.println ("Decrypt Speed Test Starting");

         while (experimentIBEDecr.isReady()!=status.ReadyVar && experimentIBEDecr.isReady()!=status.ReadyMaxExp) {
            
            client.encryptKey(binaryKey, ciphertext , inv_ciphertext, pkg.getMPK(), PkID);
            long start = System.currentTimeMillis();

//                    BigInteger quadr = SkID.modPow(BigInteger.valueOf(2), pkg.getMPK());
//                    if (quadr.compareTo(PkID) == 0) {
//                        System.out.println ("+");
                        client.decryptKey(ciphertext, SkID, pkg.getMPK(), keyLength);
//                    } else {
//                        System.out.println ("-");
//                       client.decryptKey(inv_ciphertext, SkID, pkg.getMPK(), keyLength);
//                    }
                       

                   
               
            long end = System.currentTimeMillis();
            experimentIBEDecr.addVal(end - start);
        
        }
       float avg = experimentIBEDecr.getAvg();

        if (experimentIBEDecr.isReady() == status.ReadyMaxExp) {
            out5.write("#var = " + experimentIBEDecr.lastVar +"\n");
            out5.write(keyLength+"\t"+avg+"*\n");
            System.out.println (keyLength+"\t"+avg +"*\n");
            }
        else {
            out5.write(keyLength+"\t"+avg+"\n");
            System.out.println (keyLength+"\t"+avg);
             }
       
//
//        while (experimentRSADecr.isReady()!=status.ReadyVar && experimentRSADecr.isReady()!=status.ReadyMaxExp) {
//            doFinal = cipher.doFinal(raw);
//            long start = System.currentTimeMillis();
//            byte[] decrypted = decipher.doFinal(doFinal);
//            long end = System.currentTimeMillis();
//            experimentRSADecr.addVal(end - start);
//
//
//
//        }
//        avg = experimentRSADecr.getAvg();
//        if (experimentRSADecr.isReady() == status.ReadyMaxExp) {
//             out6.write("#var = " + experimentRSADecr.lastVar +"\n");
//             out6.write(keyLength+"\t"+avg+"*\n");
//             System.out.println (keyLength+"\t"+avg +"*");
//
//            }
//        else {
//             out6.write(keyLength+"\t"+avg+"\n");
//             System.out.println (keyLength+"\t"+avg);
//
//            }
//





        
    }
        out1.close();
        out2.close();
        out3.close();
        out4.close();
        out5.close();
        out6.close();
    }



}
