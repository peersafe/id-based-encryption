
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Random;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author alex_neigum
 */
public class Main {

    public static void main_(String[] args) throws UnsupportedEncodingException, FileNotFoundException {
        PKG pkg = new PKG(14);
        System.out.println("Usage: id_based_encrypt.jar - mpk_file -msk_file -skID_file -ID");
        PrintWriter out1 = new PrintWriter(
                new OutputStreamWriter(
                new FileOutputStream(args[0]), "windows-1251"));
        PrintWriter out2 = new PrintWriter(
                new OutputStreamWriter(
                new FileOutputStream(args[1]), "windows-1251"));
        PrintWriter out3 = new PrintWriter(
                new OutputStreamWriter(
                new FileOutputStream(args[2]), "windows-1251"));
        pkg.setup();
        out1.write("" + pkg.MPK + "\n"); // write MasterPublicKey = P*Q
        out2.write("" + pkg.P + ", " + pkg.Q + "\n"); //write MasterSecretKeys P and Q
        pkg.keyExtract(args[3]);
        out3.write("" + pkg.MSK + "\n"); //write SecretKey for ID
        System.out.println("Done");
        out1.close();
        out2.close();
        out3.close();






    }
}
