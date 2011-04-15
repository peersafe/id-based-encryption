/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import org.suai.idbased.Util;
import org.suai.idbased.Sign;
import org.suai.idbased.PKG;
import org.suai.idbased.DecryptException;
import org.suai.idbased.Client;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.runner.Result;
import java.util.Arrays;
import org.junit.runner.JUnitCore;
import java.math.BigInteger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author foxneig
 */
public class MyTest {

    public MyTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of encrypt method, of class Client.
     */
    @Test
    public void testFileEncrypt() throws Exception {

        String inname = "in.txt";
        String outname = "dec.encr";
        String id = "foxneig@gmail.com";
        BigInteger skey;
        BigInteger PkID;

        PKG pkg = new PKG(512);
        pkg.setup();
        pkg.keyExtract(id);
        pkg.getSecretExponent();
        PkID = Util.genPkID(id, pkg.MPK);
        skey = pkg.signKeyExtract(id);
        Client instance = new Client();
        byte[] expResult = instance.encrypt(inname, outname, PkID, pkg.MPK, skey, pkg.e);
        byte[] result = instance.decrypt(outname, inname, id, pkg.MSK, pkg.MPK, pkg.e);
        boolean check = Arrays.equals(result, expResult);
        assertTrue(check);

    }

    @Test
    public void NegativeFileTestEncrypt() throws Exception {

        String inname = "in.txt";
        String outname = "dec.encr";
        String id = "foxneig@gmail.com";
        BigInteger skey;
        BigInteger PkID;
        PKG pkg = new PKG(512);
        pkg.setup();
        pkg.keyExtract(id);
        pkg.getSecretExponent();
        PkID = Util.genPkID(id, pkg.MPK);
        skey = pkg.signKeyExtract(id);
        Client instance = new Client();
        byte[] expResult = instance.encrypt(inname, outname, PkID, pkg.MPK, skey, pkg.e);
        id = "anotheruser@mail.dom";
        byte[] result = instance.decrypt(outname, inname, id, pkg.MSK, pkg.MPK, pkg.e);
        boolean check = Arrays.equals(result, expResult);
        assertFalse(check);

    }

    @Test
    public void TestRandomFileEncrypt() {
        try {
            PKG pkg = new PKG(512);
            Client client = new Client();
            BigInteger PkID;
            BigInteger skey;
            byte[] data_to_encrypt = null;
            byte[] decr_data = null;
            Random rand = new Random();
            String id = "user@hotmail.com";
            PrintWriter writer;
            pkg.setup();
            pkg.keyExtract(id);
            pkg.getSecretExponent();
            PkID = Util.genPkID(id, pkg.MPK);
            skey = pkg.signKeyExtract(id);
            int size = Math.abs(rand.nextInt(1000000));
            data_to_encrypt = new byte[size];
            rand.nextBytes(data_to_encrypt);
            FileOutputStream fout;
            fout = new FileOutputStream("in.txt");
            fout.write(data_to_encrypt);

            fout.close();
            data_to_encrypt = client.encrypt("in.txt", "out.dat", PkID, pkg.MPK, skey, pkg.e);
            decr_data = client.decrypt("out.dat", "decr", id, pkg.MSK, pkg.MPK, pkg.e);
            assertArrayEquals(decr_data, data_to_encrypt);


        } catch (DecryptException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Test
    public void NegativeRandomFileDecryptTest() {
        {
            FileOutputStream fout = null;
            try {
                PKG pkg = new PKG(512);
                Client client = new Client();
                BigInteger PkID;
                BigInteger skey;
                byte[] data_to_encrypt = null;
                byte[] decr_data = null;
                boolean check = false;
                String id = "user@hotmail.com";
                Random rand = new Random();
                pkg.setup();
                pkg.keyExtract(id);
                pkg.getSecretExponent();
                PkID = Util.genPkID(id, pkg.MPK);
                skey = pkg.signKeyExtract(id);
                int size = Math.abs(rand.nextInt(1000000));
                data_to_encrypt = new byte[size];
                rand.nextBytes(data_to_encrypt);
                fout = new FileOutputStream("out.dat");
                fout.write(data_to_encrypt);
                fout.close();
                decr_data = client.decrypt("out.dat", "decr", id, pkg.MSK, pkg.MPK, pkg.e);
                if (decr_data == null) {
                    check = true;
                }
                assertTrue(check);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (DecryptException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    fout.close();
                } catch (IOException ex) {
                    Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    @Test
    public void TestSign() {

        try {
            PKG pkg = new PKG(512);
            Client client = new Client();
            Sign signature = new Sign();
            BigInteger PkID;
            BigInteger skey;
            byte[] data;
            String id = "user@hotmail.com";
            Random rand = new Random();
            pkg.setup();
            pkg.keyExtract(id);
            pkg.getSecretExponent();
            PkID = Util.genPkID(id, pkg.MPK);
            skey = pkg.signKeyExtract(id);
            int size = Math.abs(rand.nextInt(1000000));
            data = new byte[size];
            rand.nextBytes(data);
            BigInteger[] sign = signature.getSign(data, skey, pkg.e, pkg.MPK);
            assertTrue(signature.verifySign(data, id, sign, pkg.e, pkg.MPK));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);

        }
    }

    @Test
    public void NegativeSignTest() {
        try {
            PKG pkg = new PKG(512);

            Sign signature = new Sign();

            BigInteger skey;
            byte[] data;
            byte[] another_data;
            String id = "user@hotmail.com";
            Random rand = new Random();
            pkg.setup();
            pkg.keyExtract(id);
            pkg.getSecretExponent();
            BigInteger PkID = Util.genPkID(id, pkg.MPK);
            skey = pkg.signKeyExtract(id);
            int size = Math.abs(rand.nextInt(1000000));
            data = new byte[size];
            another_data = new byte[size];
            rand.nextBytes(data);
            rand.nextBytes(another_data);
            BigInteger[] sign = signature.getSign(data, skey, pkg.e, pkg.MPK);
            assertFalse(signature.verifySign(another_data, id, sign, pkg.e, pkg.MPK));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Test of decrypt method, of class Client.
     */
    public static void main(String[] args) {
        JUnitCore core = new JUnitCore();
        Result res = new Result();
        int round = Integer.parseInt(args[0]);
        // Вот подключение нашего собственного слушателя/листенера
        core.addListener(new MyListener());
        core.addListener(res.createListener());
        for (int i = 0; i < round; i++) {
            core.run(MyTest.class);
        }
        System.out.println();
        System.out.println("Running time: " + res.getRunTime() / 1000 + "sec");
        System.out.println("Test's count: " + res.getRunCount());
        System.out.println("Failure: " + res.getFailureCount());

    }
}
/*Test Comment ! */
