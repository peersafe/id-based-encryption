package org.suai.idbased;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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

    private static FileOutputStream mpkf;
    private static FileOutputStream mskf;
    private static FileOutputStream default_mpkf;
    private static FileOutputStream default_mskf;
    private static DataOutputStream dmpkf;
    private static DataOutputStream default_dmpkf;
    private static DataOutputStream dmskf;
    private static DataOutputStream default_dmskf;
    private static FileOutputStream mskf2;
    private static FileOutputStream mskf1;
    private static DataOutputStream dmskf1;
    private static DataOutputStream dmskf2;
    private static FileOutputStream default_mskf1;
    private static DataOutputStream default_dmskf1;
    private static FileOutputStream default_mskf2;
    private static DataOutputStream default_dmskf2;
    private static FileOutputStream skef;
    private static DataOutputStream dskef;
    private static FileOutputStream sksf;

    public static void main(String[] args) throws UnsupportedEncodingException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, DecryptException
    {


        //Client client = new Client();
        Arguments argum = new Arguments(args);
        argum.getCommand();
        if (argum.command_type == -1)
          {
            Util.usage();
            System.exit(1);
          }
        argum.extractArgs();
        switch (argum.command_type)
          {
            case 0:
              { //setup
                argum.verifyRequiredParameters();
                int security = argum.security;
                PKG pkg = new PKG(security);
                pkg.setup();
                if (argum.mpk_path == null && argum.msk_path1 == null && argum.msk_path2 == null)
                  {
                    try
                      {
                        default_mpkf = new FileOutputStream("mpk.txt");

                        default_mpkf.write(Util.writeKeyData(pkg.MPK));
                        default_mskf1 = new FileOutputStream("msk1.txt");
                        default_mskf2 = new FileOutputStream("msk2.txt");

                        default_mskf1.write(Util.writeKeyData(pkg.P));
                        default_mskf2.write(Util.writeKeyData(pkg.Q));
                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }

                  }
                else
                  {
                    if (argum.mpk_path != null)
                      {

                        try
                          {
                            mpkf = new FileOutputStream(argum.mpk_path);

                            mpkf.write(Util.writeKeyData(pkg.MPK));
                          }
                        catch (IOException ex)
                          {
                            Logger.getLogger(Main.class.getName()).log(
                                    Level.SEVERE, null, ex);
                          }

                      }

                    if (argum.msk_path1 != null && argum.msk_path2 != null)
                      {
                        try
                          {
                            mskf1 = new FileOutputStream(argum.msk_path1);
                            mskf2 = new FileOutputStream(argum.msk_path2);

                            mskf1.write(Util.writeKeyData(pkg.P));
                            mskf2.write(Util.writeKeyData(pkg.Q));
                          }
                        catch (IOException ex)
                          {
                            Logger.getLogger(Main.class.getName()).log(
                                    Level.SEVERE, null, ex);
                          }


                      }

                  }



                break;

              }
            case 1:
              { //keyExtract
                argum.verifyRequiredParameters();
                PKG pkg = new PKG();
                if (argum.mpk_path == null)
                  { // дефолтные ключи
                    try
                      {
                        // дефолтные ключи
                        pkg.MPK = Util.readKeyData(
                                new FileInputStream("mpk.txt"));
                        pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                        pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                        BigInteger SKE = pkg.keyExtract(argum.id);
                        pkg.getSecretExponent();
                        BigInteger SKS = pkg.signKeyExtract(argum.id);
                        skef = new FileOutputStream(argum.sk_path);
                        sksf = new FileOutputStream(argum.sks_path);

                        skef.write(Util.writeKeyData(SKE));
                        sksf.write(Util.writeKeyData(SKS));

                        skef.close();
                        sksf.close();


                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }


                  }
                else
                  { // подсовываем другие ключи
                    try
                      {
                        pkg.MPK = Util.readKeyData(new FileInputStream(
                                argum.mpk_path));
                        pkg.P = Util.readKeyData(new FileInputStream(
                                argum.msk_path1));
                        pkg.Q = Util.readKeyData(new FileInputStream(
                                argum.msk_path2));
                        BigInteger SKE = pkg.keyExtract(argum.id);
                        pkg.getSecretExponent();
                        BigInteger SKS = pkg.signKeyExtract(argum.id);
                        skef = new FileOutputStream(argum.sk_path);
                        sksf = new FileOutputStream(argum.sks_path);
                        skef.write(Util.writeKeyData(SKE));
                        sksf.write(Util.writeKeyData(SKS));
                        sksf.close();
                        skef.close();
                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }

                  }
                break;

              }
            case 2:
              { //encrypt
                PKG pkg = new PKG();
                Client client = new Client();
                argum.verifyRequiredParameters();
                if (argum.mpk_path == null)
                  {
                    pkg.MPK = Util.readKeyData(new FileInputStream("mpk.txt"));
                    //pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                    //pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                    pkg.getSecretExponent();
                    client.encryptData(argum.in_path, argum.out_path, client.
                            genPkID(argum.id, pkg.MPK), pkg.MPK, pkg.
                            signKeyExtract(argum.id), pkg.e);
                  }
                else
                  {
                    pkg.MPK = Util.readKeyData(new FileInputStream(
                            argum.mpk_path));
                    pkg.P = Util.readKeyData(
                            new FileInputStream(argum.msk_path1));
                    pkg.Q = Util.readKeyData(
                            new FileInputStream(argum.msk_path2));
                    pkg.getSecretExponent();
                    client.encryptData(argum.in_path, argum.out_path, client.
                            genPkID(argum.id, pkg.MPK), pkg.MPK, pkg.
                            signKeyExtract(argum.id), pkg.e);


                  }
                break;
              }
            case 3:
              { //decrypt
                PKG pkg = new PKG();
                Client client = new Client();
                argum.verifyRequiredParameters();
                if (argum.mpk_path == null)
                  {
                    pkg.MPK = Util.readKeyData(new FileInputStream("mpk.txt"));
                    pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                    pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                    BigInteger SKE = Util.readKeyData(new FileInputStream(
                            argum.sk_path));
                    byte[] data = client.decryptData(argum.in_path,
                            argum.out_path, argum.id, SKE, pkg.MPK, pkg.e);
                    if (data == null)
                      {
                        System.out.println(
                                "Не удалось расшифровать, возможно вы используете не тот ключ");
                      }
                  }
                else
                  {
                    pkg.MPK = Util.readKeyData(new FileInputStream(
                            argum.mpk_path));
                    pkg.P = Util.readKeyData(
                            new FileInputStream(argum.msk_path1));
                    pkg.Q = Util.readKeyData(
                            new FileInputStream(argum.msk_path2));
                    BigInteger SKE = Util.readKeyData(new FileInputStream(
                            argum.sk_path));
                    byte[] data = client.decryptData(argum.in_path,
                            argum.out_path, argum.id, SKE, pkg.MPK, pkg.e);
                    if (data == null)
                      {
                        System.out.println(
                                "Не удалось расшифровать, возможно вы используете не тот ключ");
                      }


                  }
                break;
              }
            case 4:
              { //sign
                argum.verifyRequiredParameters();
                PKG pkg = new PKG();
                Sign signature = new Sign();
                if (argum.mpk_path == null)
                  { // дефолтные ключи
                    try
                      {
                        // дефолтные ключи
                        pkg.MPK = Util.readKeyData(
                                new FileInputStream("mpk.txt"));
                        pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                        pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                        BigInteger SKS = Util.readKeyData(new FileInputStream(
                                argum.sks_path));
                        pkg.getSecretExponent();
                        signature.signFile(argum.in_path, argum.out_path,
                                argum.id, SKS, pkg.MPK, pkg.e);



                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }


                  }
                else
                  { // подсовываем другие ключи
                    try
                      {
                        pkg.MPK = Util.readKeyData(new FileInputStream(
                                argum.mpk_path));
                        pkg.P = Util.readKeyData(new FileInputStream(
                                argum.msk_path1));
                        pkg.Q = Util.readKeyData(new FileInputStream(
                                argum.msk_path2));
                        BigInteger SKS = Util.readKeyData(new FileInputStream(
                                argum.sks_path));
                        pkg.getSecretExponent();
                        signature.signFile(argum.in_path, argum.out_path,
                                argum.id, SKS, pkg.MPK, pkg.e);
                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }

                  }
                break;

              }
            case 5:
              {//verify_sign
                argum.verifyRequiredParameters();
                PKG pkg = new PKG();
                Sign signature = new Sign();
                if (argum.mpk_path == null)
                  { // дефолтные ключи
                    try
                      {
                        // дефолтные ключи
                        pkg.MPK = Util.readKeyData(
                                new FileInputStream("mpk.txt"));
                        pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                        pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                        //                   pkg.getSecretExponent();
                        signature.verifySignedFile(argum.in_path, pkg.e, pkg.MPK);



                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }


                  }
                else
                  { // подсовываем другие ключи
                    try
                      {
                        pkg.MPK = Util.readKeyData(
                                new FileInputStream("mpk.txt"));
                        pkg.P = Util.readKeyData(new FileInputStream("msk1.txt"));
                        pkg.Q = Util.readKeyData(new FileInputStream("msk2.txt"));
                        //                   pkg.getSecretExponent();
                        signature.verifySignedFile(argum.in_path, pkg.e, pkg.MPK);
                      }
                    catch (IOException ex)
                      {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE,
                                null, ex);
                      }

                  }
                break;


              }
            case 6:
              {
                Util.help();
                System.exit(1);
                break;

              }
            default:
              {
              }
          }
    }
}
/*Testing svn */
