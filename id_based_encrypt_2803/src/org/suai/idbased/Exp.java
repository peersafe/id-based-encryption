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
        if (var <= threshold) return status.ReadyVar;
        if (expNum >= maxExpNum) return status.ReadyMaxExp;
        return status.NotReady;
   


    }
    public static void main (String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        /* Init IDbasedEncryption */

        PKG pkg = new PKG(512);
        pkg.setup();
        BigInteger PkID = pkg.genPkID("user@example.com", pkg.getMSK1(), pkg.getMSK2(), pkg.getMPK());
        Random rand = new Random ();
        Client client = new Client();
        FileWriter out1 = new FileWriter ("/home/foxneig/IBE_times.txt", true);
        FileWriter out2 = new FileWriter ("/home/foxneig/RSA_times.txt", true);
        FileWriter out3 = new FileWriter ("/home/foxneig/IBE_ciphlength.txt", true);
        FileWriter out4 = new FileWriter ("/home/foxneig/RSA_ciphlength.txt",true);
         /*Init RSA Encryption */
         Cipher cipher = Cipher.getInstance("RSA");
         KeyPairGenerator Kgen = KeyPairGenerator.getInstance("RSA");
         Kgen.initialize(1024);
         KeyPair kpair = Kgen.generateKeyPair();
         cipher.init(Cipher.ENCRYPT_MODE, kpair.getPublic());
         byte[] doFinal = null;

         int keyLength = 0;


        


        for (keyLength = 64; keyLength <= 512; keyLength = keyLength*2) {
        System.out.println ("KeyLength = " + keyLength);
        byte [] raw = new byte [keyLength/8];
        rand.nextBytes(raw);
        byte[] binaryKey = Util.KeyToBinary(raw);
        BigInteger[] ciphertext = new BigInteger [binaryKey.length];
        BigInteger[] inv_ciphertext = new BigInteger [binaryKey.length];
        Exp experimentIBE = new Exp (2000, 15000, (float) 0.15);
        Exp experimentRSA = new Exp (2000, 15000, (float) 0.15);
      
        System.out.println ("IBE started");
        while (experimentIBE.isReady()!=status.ReadyVar && experimentIBE.isReady()!=status.ReadyMaxExp) {
           
            long start = System.currentTimeMillis();
            client.encryptKey(binaryKey, ciphertext , inv_ciphertext, pkg.getMPK(), PkID);
            long end = System.currentTimeMillis();
        //    System.out.println ("avg: " +experimentIBE.lastAvg +"disp:" + experimentIBE.lastDisp);

            experimentIBE.addVal(end - start);


        }
        float avg = experimentIBE.getAvg();
        int l = 0;
         for (int i = 0; i < ciphertext.length; i++) {
             l = l + ciphertext[i].toByteArray().length + inv_ciphertext[i].toByteArray().length;
         }
        if (experimentIBE.isReady() == status.ReadyMaxExp) {
            out1.write(""+keyLength+" "+""+avg +"*\n");
            out3.write (""+keyLength+" "+""+l);
            System.out.println (""+keyLength+" "+""+l);
            System.out.println (""+keyLength+" "+""+avg +"*\n");
            }
        else {
            out1.write(""+keyLength+" "+""+avg);
            out3.write (""+keyLength+" "+""+l);
            System.out.println (""+keyLength+" "+""+avg);
            System.out.println (""+keyLength+" "+""+l);
            }
        System.out.println ("RSA started");
        while (experimentRSA.isReady()!=status.ReadyVar && experimentRSA.isReady()!=status.ReadyMaxExp) {
            
            long start = System.currentTimeMillis();
            doFinal = cipher.doFinal(raw);
            long end = System.currentTimeMillis();
           // System.out.println ("avg: " +experimentRSA.lastAvg +"disp:" + experimentRSA.lastDisp);
            experimentRSA.addVal(end - start);


        }
        avg = experimentRSA.getAvg();
        if (experimentRSA.isReady() == status.ReadyMaxExp) {
             out2.write(""+keyLength+" "+""+avg +"*\n");
             out4.write(""+keyLength+" "+""+doFinal.length);
             System.out.println (""+keyLength+" "+""+avg +"*\n");
              System.out.println (""+keyLength+" "+""+doFinal.length);
            }
        else {
             out2.write(""+keyLength+" "+""+avg);
             out4.write(""+keyLength+" "+""+doFinal.length);
             System.out.println (""+keyLength+" "+""+avg);
             System.out.println (""+keyLength+" "+""+doFinal.length);
            }



        
    }
        out1.close();
        out2.close();
        out3.close();
        out4.close();
    }



}
