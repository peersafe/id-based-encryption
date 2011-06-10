package org.suai.idbased.util;

import org.suai.idbased.crypto.Cryptocontainer;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.suai.idbased.crypto.Cryptocontainer;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author alex_neigum
 */
public class Util {

    static public byte[] KeyToBinary(byte[] raw)
    {
        StringBuffer sb = new StringBuffer();
        byte[] binaryKey;
        for (int i = 0; i < raw.length; i++)
          {
            String binary = null;
            binary = Integer.toBinaryString(raw[i] & 0xff);
            if (binary.length() < 8)
              {
                for (int k = 0; k < 8 - binary.length(); k++)
                  {
                    sb.append("0");
                  }
              }
            sb.append(binary);

          }
        binaryKey = new byte[sb.length()];
        for (int i = 0; i < sb.length(); i++)
          {
            binaryKey[i] = sb.charAt(i) == '0' ? (byte) 0 : (byte) 1;
          }
        return binaryKey;

    }

    static public void GetEncryptedKey(DataInputStream din, boolean keytype,
                                Cryptocontainer cc,
                                BigInteger[] encrypted_aes_key) throws IOException
    {
        int size_of_encr_keybyte;
        din.skipBytes(8);
        if (keytype == false)
          {
            for (int i = 0; i < 128; i++)
              {
                size_of_encr_keybyte = din.readInt();

                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);


              }
            din.skipBytes(cc.secondKeySize);
          }
        else
          {
            din.skipBytes(cc.firstKeySize);
            for (int i = 0; i < 128; i++)
              {
                size_of_encr_keybyte = din.readInt();
                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);

              }
          }
    }

    static public byte[] BinaryToByteKey(int[] binary_aes_key)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < binary_aes_key.length; i++)
          {
            sb.append(binary_aes_key[i]);
          }

        int from = 0, to = 8;
        String byte_of_key = new String();
        byte[] raw = new byte[16];
        String aes_key = sb.toString();
        for (int i = 0; i < 16; i++)
          {
            byte_of_key = aes_key.substring(from, to);


            raw[i] = Integer.valueOf(byte_of_key, 2).byteValue();
            from = to;
            to = to + 8;
          }
        return raw;
    }

    static public void usage()
    {   System.out.println ("\n");
        System.out.println("--Clifford Cocks Identity Based Cryptosystem for mail server --");
        System.out.println("");
        System.out.println("To run the program, type the following:");
        System.out.println("java -jar id_based_encrypt.jar command [parameters]");
        System.out.println("List of available commands:");
        System.out.println("setup");
        System.out.println("keyextract");
        System.out.println("encrypt");
        System.out.println("decrypt");
        System.out.println("sign");
        System.out.println("verify");
        System.out.println(
                "Print --help to see the details information of the program usage");


    }

    static public void help()
    {   System.out.println("\n");
        System.out.println ("Before the first use of the program, initialize, run the program with the setup command!");
        System.out.println(
                "Please note: the sign [] marked optional parameters, parameter order is irrelevant");
        System.out.println();
        System.out.println("------------------");
        System.out.println("About setup:");
        
        System.out.println(
                "Setup performs the initialization of Public Key Generator - "
                + "generate the necessary parameters for the cryptosystem, namely:");
        System.out.println(
                "-MasterPublicKey generation of a given length (parameter security)");
        System.out.println(
                "-MasterSecretKey generation of a given length (parameter security)");
        System.out.println("If necessary, these settings are stored in files specified by the user"
                + "(parameters -msk and -mpk)");
        System.out.println ("Otherwise, they are saved in the default directory");
        System.out.println();
        System.out.println("Usage:");
        System.out.println(
                "setup  -security 'positive integer' [-mpk 'file_path' -msk 'file_path1' 'file_path2']");
        System.out.println("------------------");

        System.out.println("------------------");
        System.out.println("About keyextract:");
        
        System.out.println(
                "KeyExtract generates a secret key for encryption and signature for a user specified text identifier");
        System.out.println ("In this case, you must specify the path to the master public key system, generated by running setup (if you are running with the -mpk parameter)");
        System.out.println();
        System.out.println("Usage");
        System.out.println(
                "keyextract [-mpk 'the_path_to_a_master_public_key -msk 'file_path1' 'file_path2' ]'-sk 'output_path_to_the_encryption_secret_key' -sks 'output_path_to_the_signing_secret_key'  -id 'e-mail adress'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About encrypt:");
        
        System.out.println(
                "encrypt makes encryption and signature of a user-specified file");
        System.out.println("Usage:");
        System.out.println(
                "encrypt [-mpk 'the_path_to_a_master_public_key' -msk 'file_path1' 'file_path2']  -id 'e-mail adress'"
                + "-in 'path_to_the_file_for_encryption' -out 'output_path_to_the_encrypted_file'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About decrypt");
       
        System.out.println(
                "decrypt makes decryption and signature verification previously encrypted files");
        System.out.println("Usage:");
        System.out.println(
                "decrypt [-mpk 'the_path_to_a_master_public_key' -msk 'file_path1' 'file_path2' ] -sk 'the_path_to_a_encryption_secret_key'"
                + "-in 'path_to_the_encrypted_file' -out 'output_path_to_the_decrypted_file' -id 'e-mail adress'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About sign");

        
        System.out.println(
                "sign produces a signature of a user-specified file");
        System.out.println("Usage:");
        System.out.println(
                "sign  [-mpk 'the_path_to_a_master_public_key'-msk 'file_path1' 'file_path2' ] -sks 'the_path_to_a_signed_secret_key'  -id 'e-mail adress' -out 'output_path_to_a_signed_file'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About verify");
       
        System.out.println(
                "verify checks the signature and returns the result");
        System.out.println("Usage:");
        System.out.println(
                "verify [-mpk 'the_path_to_a_master_public_key'-msk 'file_path1' 'file_path2' ] -in 'path_to_a_signed_file' ");
        System.out.println("------------------");
    }

    static public void invalidParameters()
    {
        System.out.println(
                "Entered incorrect settings or missing required parameters, type --help for calling tips");
    }

    static public byte[] writeKeyData(BigInteger data)
    {
//        BASE64Encoder enc = new BASE64Encoder();
//
//        String encoded = enc.encode(data.toByteArray());

        return data.toByteArray();

    }

    static public BigInteger readKeyData(FileInputStream in) throws IOException
    {
//        BASE64Decoder dec = new BASE64Decoder ();
//        BigInteger key = new BigInteger(dec.decodeBufferToByteBuffer(in).array());
        int length = in.available();
        byte[] byte_key = new byte[length];
        in.read(byte_key);
        BigInteger key = new BigInteger(byte_key);
        return key;

    }
}
