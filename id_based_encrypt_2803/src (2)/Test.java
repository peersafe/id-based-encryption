
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author alex_neigum
 */
public class Test {


    void testExtract (int round, String id) throws UnsupportedEncodingException, FileNotFoundException {
        PrintWriter writer = new PrintWriter(
             new OutputStreamWriter(
             new FileOutputStream("TestExtractErrors.txt"), "windows-1251"));
        long PkID = 0;
        long quadr = 0;
        PKG pkg = new PKG (14);
    for (int i = 0; i < round; i++) {
    pkg.setup();
    pkg.keyExtract(id);
    PkID = Util.genPkID(id, pkg.MPK);
    quadr = ResidueCalculation.powmod(pkg.MSK, 2, pkg.MPK);

    if (quadr ==  PkID || quadr == pkg.MPK - PkID)
        ;
    else {
        writer.write("------------Experiment # " +i+"------------"+"\n");
        writer.write("MasterPublicKey = "+pkg.P + "*"+pkg.Q +" = "+pkg.MPK + "\n");
        writer.write ("Public Key: "+PkID + "\n");
        writer.write ("Jacobi("+PkID+","+pkg.P+")= "+ ResidueCalculation.Jacobi(PkID, pkg.P)+"\n");
        writer.write ("Jacobi("+PkID+","+pkg.Q+")= "+ ResidueCalculation.Jacobi(PkID, pkg.Q)+"\n");
        writer.write ("MasterSecretKey = "+pkg.MSK+"\n");

        writer.write ("Error! \n");

        }
}
    writer.close();
    }
    void testEncrypt (int round, String id) throws UnsupportedEncodingException, FileNotFoundException {
    Client client = new Client();
    PKG pkg = new PKG(14);
    long PkID = 0;
    long[] encrypt = new long[2];
    int message;
    int decrypt1;
    int decrypt2;
    Random rand = new Random();
    PrintWriter writer = new PrintWriter(
             new OutputStreamWriter(
             new FileOutputStream("TestEncryptError.txt"), "windows-1251"));
    for (int i = 0; i < round; i++) {

        pkg.setup();
        pkg.keyExtract(id);
        PkID = Util.genPkID(id,pkg.MPK);
       

        message = Math.abs(rand.nextInt())%2;
        encrypt = client.encrypt(message, PkID, pkg.MPK);
        
        decrypt1 = client.decrypt(encrypt[0], pkg.MSK, pkg.MPK);
       
        decrypt2 = client.decrypt(encrypt[1], pkg.MSK, pkg.MPK);

        if (decrypt1!=message && decrypt2!=message) {
        writer.write("MasterPublicKey = "+pkg.P + "*"+pkg.Q +" = "+pkg.MPK + "\n");
        writer.write ("Public Key: "+PkID + "\n");
        writer.write ("Cleartext: "+message+"\n");
        writer.write ("Ciphertext for a: "+encrypt[0]+"\n");
        writer.write ("Ciphertext for -a: "+encrypt[1]+"\n");
        writer.write ("Decrypted for a: "+decrypt1+"\n");
         writer.write ("Decrypted for -a: "+decrypt2+"\n");
        }




    }

    }
    void TestFileEncrypt (long num, String id ) throws UnsupportedEncodingException, FileNotFoundException{
        PKG pkg = new PKG (14);
        ClientNew client = new ClientNew();
        long PkID;
        long skey;
        byte [] data_to_encrypt = null;
        byte [] decr_data = null;
        int err_num = 0;
        PrintWriter writer = new PrintWriter(
             new OutputStreamWriter(
             new FileOutputStream("TestEncryptError.txt"), "windows-1251"));
        for (int i = 0; i < num; i++) {
            if (i%1000 == 0 ) System.out.println ("Experiment "+i);

        pkg.setup();
        pkg.keyExtract(id);
        pkg.getSecretExponent();
        PkID = Util.genPkID(id, pkg.MPK);
        skey = pkg.signKeyExtract(id);
            try {
                data_to_encrypt = client.encrypt("in.txt", "out.dat", PkID, pkg.MPK, skey, pkg.e);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                decr_data = client.decrypt("out.dat", "decr", id, pkg.MSK, pkg.MPK, pkg.e);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
              //  err_num++;
                decr_data = null;
                writer.write ("javax.crypto.BadPaddingException: Given final block not properly padded \n");
                continue;
                //Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            }
        if (Arrays.equals(data_to_encrypt, decr_data) == false) {
            err_num++;
            writer.write("MasterPublicKey = "+pkg.P + "*"+pkg.Q +" = "+pkg.MPK + "\n");
            writer.write ("Public Key: "+PkID + "\n");
            writer.write ("Secret exponent: "+pkg.d +"\n");
            writer.write ("Secret signed key:" +pkg.SSK +"\n");

        }


        }
        writer.write ("Err_number: "+err_num +"\n");
        writer.close();
    }
    void NegativeDecryptTest (long num, String id) throws UnsupportedEncodingException, FileNotFoundException, IOException {
        PKG pkg = new PKG (14);
        ClientNew client = new ClientNew();
        long PkID;
        long skey;
        byte [] data_to_encrypt = null;
        byte [] decr_data = null;
        int err_num = 0;
        Random rand = new Random();




        PrintWriter writer = new PrintWriter(
             new OutputStreamWriter(
             new FileOutputStream("TestEncryptError.txt"), "windows-1251"));
        for (int i = 0; i < num; i++) {
            if (i%1000 == 0 ) System.out.println ("Experiment "+i);
        pkg.setup();
        pkg.keyExtract(id);
        pkg.getSecretExponent();
        PkID = Util.genPkID(id, pkg.MPK);
        skey = pkg.signKeyExtract(id);
        int size = Math.abs(rand.nextInt());
        data_to_encrypt = new byte[size];
        rand.nextBytes(data_to_encrypt);
        FileOutputStream fout = new FileOutputStream ("out.dat");
        fout.write(data_to_encrypt);
        fout.close();
            try {
                decr_data = client.decrypt("out.dat", "decr", id, pkg.MSK, pkg.MPK, pkg.e);
                data_to_encrypt = null;
            } catch (IOException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
            }
            if (decr_data != null) {
            System.out.println ("Error");
            writer.write("MasterPublicKey = "+pkg.P + "*"+pkg.Q +" = "+pkg.MPK + "\n");
            writer.write ("Public Key: "+PkID + "\n");
            writer.write ("Secret exponent: "+pkg.d +"\n");
            writer.write ("Secret signed key:" +pkg.SSK +"\n");

            }
    }
    }





public static void main (String[] args) throws UnsupportedEncodingException, FileNotFoundException, IOException {
    
   
    long quadr;
    Test test = new Test();


 //   test.testExtract(1000);
   // System.out.println ("TestExtract \n");
    //test.testExtract(1000000000, "foxneig12345@exampleserver.com");
    //System.out.println ("TestEncrypt \n");
    //test.testEncrypt(1000000000, "foxneig12345@exampleserver.com");
   // test.TestFileEncrypt(100000, "foxneig@gmail.com");
    test.NegativeDecryptTest(1000, "foxneig@gmail.com");

    
  
    }
}
