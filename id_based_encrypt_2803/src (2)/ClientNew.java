
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
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
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
 * @author alex_neigum
 */
public class ClientNew {
BigInteger [] getSign (byte [] message, long skey, long pkey, long MPK) throws NoSuchAlgorithmException {
    Random rand = new Random ();
    long r = Math.abs(rand.nextInt()%MPK);
    long T = ResidueCalculation.powmod(r, pkey, MPK); // t = r^e mod N
    BigInteger m = new BigInteger(message);
    //System.out.println ("Message is: "+m.toString());
    BigInteger t = new BigInteger(Long.toString(T));
    //System.out.println ("t = r^e mod N = "+t.toString());
    BigInteger xor = m.xor(t);
    //System.out.println ("M||t = " + xor.toString());
    MessageDigest MD = MessageDigest.getInstance("SHA");
    byte [] data = xor.toByteArray();
    MD.update(data);
    byte [] hash = MD.digest();
    BigInteger exp = new BigInteger (hash);
    exp = exp.abs();
    //System.out.println ("Hash(M||t) = " + exp.toString());
    BigInteger g = BigInteger.valueOf(skey);
    //System.out.println ("Secret Key g = "+g.toString());
    BigInteger s = g.multiply(BigInteger.valueOf(r).modPow(exp, BigInteger.valueOf(MPK)));
    s =  s.mod(BigInteger.valueOf(MPK));
    //System.out.println ("Sign: "+s.toString());
    BigInteger [] sign = new BigInteger[2];
    sign[0] = t;
    sign[1] = s;
    return sign;
}
boolean verifySign (byte [] message, String id, BigInteger [] sign,long pkey, long MPK) throws NoSuchAlgorithmException {
    long _id = Math.abs(id.hashCode()%32);
    BigInteger m = new BigInteger(message);
    //System.out.println ("Message is: "+m.toString());
    BigInteger xor = m.xor(sign[0]);
    //System.out.println ("M||t = " + xor.toString());
    MessageDigest MD = MessageDigest.getInstance("SHA");
    byte [] data = xor.toByteArray();
    MD.update(data);
    byte [] hash = MD.digest();
    BigInteger exp = new BigInteger (hash);
    exp = exp.abs();
    //System.out.println ("Hash(M||t) = " + exp.toString());
    BigInteger verify = BigInteger.valueOf(_id).multiply(sign[0].modPow(exp, BigInteger.valueOf(MPK)));
    verify = verify.mod(BigInteger.valueOf(MPK));
    return verify.equals(sign[1].modPow(BigInteger.valueOf(pkey), BigInteger.valueOf(MPK)));







}
byte [] encrypt (String inname, String outname, long PkID, long MPK, long sk, long pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        int t;
        int m = 0;
        int  j;
        long s,s1;
        int bit;
        String binary = null;
        StringBuffer sb = new StringBuffer();
        CipherInputStream cis;
        long inv_t;
        FileOutputStream fout = new FileOutputStream (outname);
        FileInputStream fin = new FileInputStream (inname);
        DataOutputStream dos = new DataOutputStream (fout);
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
       SecretKey skey = kgen.generateKey();
       byte[] raw = skey.getEncoded();
     //  for (int i = 0; i < raw.length; i++) {
     //      if (raw[i] < 0) raw[i]*=-1;
    //   }

       SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
       Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
       cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
       
       for (int i = 0; i < raw.length; i++) {

       binary = Integer.toBinaryString(raw[i]&0xff);
       if (binary.length() < 8)
           for (int k = 0; k < 8-binary.length(); k++)
                sb.append("0");
       sb.append(binary);
       
       }
       long[] ciphertext = new long[sb.length()];
       long[] inv_ciphertext = new long [sb.length()];
       for (int i = 0; i < sb.length(); i++) {
           m = Character.digit(sb.charAt(i), 10);
           Random rand = new Random ();

        while (true) {
        t = (int) (rand.nextInt() % MPK);
        j = ResidueCalculation.Jacobi(t, MPK);
        //+1 = 1; -1 = 0
        if ( m == 0 && j == -1) {
           inv_t =  ResidueCalculation.inv(t, MPK);
           ciphertext[i] = (t + PkID*inv_t)%MPK;
           inv_ciphertext[i] =(t - PkID*inv_t)%MPK;
           if (inv_ciphertext[i] < 0) inv_ciphertext[i] = MPK + inv_ciphertext[i];


            break;
        }
 else
     if ( m == 1 && j == 1) {
         inv_t =  ResidueCalculation.inv(t, MPK);
         ciphertext[i] = (t + PkID*inv_t)%MPK;
         inv_ciphertext[i] =(t - PkID*inv_t)%MPK;
         if (inv_ciphertext[i] < 0) inv_ciphertext[i] = MPK + inv_ciphertext[i];

         break;

     }
        }



       }
       //записываем ключевую информацию
       for (int i = 0; i < ciphertext.length; i++)
           dos.writeLong(ciphertext[i]);
       for (int i = 0; i < inv_ciphertext.length; i++)
           dos.writeLong(inv_ciphertext[i]);
       int data_size = fin.available(); // размер шифруемых данных
       
       byte [] data_to_encrypt = new byte [data_size];
       fin.read(data_to_encrypt);
       //byte[] buffer= cipher.update(data_to_encrypt);
       byte[] encrypted_data = cipher.doFinal(data_to_encrypt);
       int encrypted_data_size = encrypted_data.length;
       dos.writeInt(encrypted_data_size);
       //fout.write (encrypted_data);
       dos.write(encrypted_data);



       

//      cis = new CipherInputStream(fin, cipher);
//      byte[] b = new byte[8];
//
//      int i = cis.read(b);
//      while (i != -1) {
//        fout.write(b, 0, i);
//        i = cis.read(b);
//    }
      
      FileInputStream fis = new FileInputStream (outname);
    //  MessageDigest MD = MessageDigest.getInstance("SHA");
      byte [] data_to_hash = new byte[fis.available()];
      fis.read(data_to_hash);
      //MD.update(data_to_hash);
      //byte[] hash = MD.digest();
      BigInteger [] sign = new BigInteger[2];
      sign = this.getSign(data_to_hash, sk, pk, MPK);
 
    
     dos.writeLong(sign[0].longValue());
     dos.writeLong(sign[1].longValue());
     dos.close();
     fout.close();
     fis.close();
     return data_to_encrypt;

      


     




        

    }
byte[] decrypt (String inname, String outname, String id, long SkID, long MPK, long pkey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecryptException {
        // r^2 = a mo M or r^2 = -a mod M
        boolean negative = false;
        long [] encrypted_aes_key = new long [128];
        long pk = Util.genPkID(id, MPK);
        long quadr = ResidueCalculation.powmod(SkID, 2, MPK);
        if ( quadr == pk) {
          negative = false;
        }
        else {
            negative = true;
      //      System.out.println ("Use negative key");
    }
        FileInputStream fin = new FileInputStream(inname);
        DataInputStream ds = new DataInputStream(fin);
        int data_size = fin.available();
        if (data_size-16 <= 0) return null;
        byte [] data = new byte[data_size-16]; // data_size - sizeof(MPK)*2
        ds.read(data);
        String s;
        String key;
        BigInteger [] sign = new BigInteger [2];
        long t = ds.readLong();
        long S = ds.readLong();
        sign[0] = BigInteger.valueOf(t);
        sign[1] = BigInteger.valueOf(S);
        boolean verify_sign = this.verifySign(data, id , sign, pkey, MPK);
        //System.out.println ("Sign :" +verify_sign);
        if (verify_sign == false) return null;

        fin.close();
        ds.close();
        fin = new FileInputStream (inname);
        DataInputStream din = new DataInputStream (fin);

        if ( negative == false) {
            for (int i = 0; i < 128; i++)
                encrypted_aes_key[i] = din.readLong();
                din.skipBytes(128*8);
        }

 else
        {
            din.skipBytes(128*8);
            for (int i = 0; i < 128; i++)
                encrypted_aes_key[i] = din.readLong();
    }

        int [] binary_aes_key = new int [128];
        for (int i = 0; i < 128; i++) {
        int Jacobi = ResidueCalculation.Jacobi((encrypted_aes_key[i] + 2 * SkID)%MPK, MPK);

       if (Jacobi == 1)
           binary_aes_key[i] = 1;
        else
            if (Jacobi == -1)
                binary_aes_key[i] = 0;
            else {
                 binary_aes_key[i] = 0; // error
                 throw new DecryptException((encrypted_aes_key[i] + 2 * SkID)%MPK, SkID, MPK);
    }
    }
        StringBuffer sb = new StringBuffer ();
        for (int i = 0; i < binary_aes_key.length; i++) {
      //      System.out.print (""+binary_aes_key[i]);
            sb.append(binary_aes_key[i]);
        }
       int from = 0, to = 8;
       String byte_of_key = new String ();
       byte [] raw = new byte [16];
       String aes_key =  sb.toString();
       for (int i = 0; i < 16; i++) {
       byte_of_key = aes_key.substring(from,to);

     //  raw[i] = Byte.parseByte(byte_of_key, 2);
       raw[i] =  Integer.valueOf(byte_of_key, 2).byteValue();
       from = to;
       to = to + 8;
       }
       int encrypted_data_size = din.readInt();
       din.close ();
       SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
       Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
       cipher.init(Cipher.DECRYPT_MODE, skeySpec);
       byte [] encrypted_data = new byte [encrypted_data_size];
       for (int i = 2052; i < data.length; i++) {
           encrypted_data [i-2052] = data[i];
       }
       byte [] decrypted_data = cipher.doFinal(encrypted_data);
       FileOutputStream fos = new FileOutputStream (outname);
       fos.write(decrypted_data);
       fos.close();
       return decrypted_data;

    }
public static void main_ (String[] args) throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
//    PKG pkg = new PKG (14);
//    String id = "foxneig@gmail.com";
//    pkg.setup();
//    pkg.keyExtract(id);
//    pkg.getSecretExponent();
//    long PkID = Util.genPkID(id, pkg.MPK);
//    ClientNew client = new ClientNew();
////    args[0] = "in.pdf";
////    args[1] = "out";
////    if (args.length < 2) {
////        System.out.println ("Usage id_based_encrypt.jar -in -out");
////        System.exit(0);
////    }
//    long skey = pkg.signKeyExtract("foxneig@gmail.com");
//    byte [] data_to_encrypt  = client.encrypt("in.txt", "out.dat", PkID, pkg.MPK, skey, pkg.e);
//    byte [] decr_data = client.decrypt("out.dat", "decr", pkg.MSK, pkg.MPK, pkg.e);
//    System.out.println ("Decrypt: "+Arrays.equals(data_to_encrypt, decr_data));
//
//
//
////   BigInteger [] sign = client.getSign(decr_key, skey, pkg.e, pkg.MPK);
////  // decr_key[0] = 15;
////  System.out.println ("Status: "+ client.verifySign(decr_key, id, sign, pkg.e, pkg.MPK));
  

}
}
