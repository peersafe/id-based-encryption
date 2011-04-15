package org.suai.idbased;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
public class Main {

    public static void main(String[] args) throws UnsupportedEncodingException, FileNotFoundException, NoSuchAlgorithmException {
        try {
            PKG pkg = new PKG(512);
            Client client = new Client();
            if (args.length < 6) {
                System.out.println("Usage: id_based_encrypt.jar - mpk_file -msk_file -skID_file -ID -file_to_encrypt -file_to_decrypt");
                System.exit(1);
            }
            PrintWriter out1 = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), "windows-1251"));
            PrintWriter out2 = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[1]), "windows-1251"));
            PrintWriter out3 = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[2]), "windows-1251"));
            pkg.setup();
            out1.write("" + pkg.MPK.toString() + "\n"); // write MasterPublicKey = P*Q
            out2.write("" + pkg.P.toString() + ", " + pkg.Q.toString() + "\n"); //write MasterSecretKeys P and Q
            pkg.keyExtract(args[3]);
            out3.write("" + pkg.MSK + "\n"); //write SecretKey for ID
            System.out.println("Starting encrypting file: " + args[4]);
            client.encrypt(args[4], "encrypted", Util.genPkID(args[3], pkg.MPK), pkg.MPK, pkg.signKeyExtract(args[3]), pkg.e);
            System.out.println("Starting decrypting file");
            client.decrypt("encrypted", args[5], args[3], pkg.MSK, pkg.MPK, pkg.e);
            System.out.println("Done");
            out1.close();
            out2.close();
            out3.close();
        } catch (DecryptException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }






    }
}
