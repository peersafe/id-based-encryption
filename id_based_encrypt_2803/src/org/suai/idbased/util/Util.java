package org.suai.idbased.util;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.suai.idbased.crypto.Cryptocontainer;

public class Util {
    private final static int aesKeyLen = 128;

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
                                BigInteger[] encryptedAESKey) throws IOException
    {
        int sizeofEncrAESKeyBit;
        din.skipBytes(8);
        if (keytype == false)
          {
            for (int i = 0; i < aesKeyLen; i++)
              {
                sizeofEncrAESKeyBit = din.readInt();

                byte[] buff = new byte[sizeofEncrAESKeyBit];
                din.read(buff);
                encryptedAESKey[i] = new BigInteger(buff);


              }
            din.skipBytes(cc.secondKeySize);
          }
        else
          {
            din.skipBytes(cc.firstKeySize);
            for (int i = 0; i < aesKeyLen; i++)
              {
                sizeofEncrAESKeyBit = din.readInt();
                byte[] buff = new byte[sizeofEncrAESKeyBit];
                din.read(buff);
                encryptedAESKey[i] = new BigInteger(buff);

              }
          }
    }

    static public byte[] BinaryToByteKey(int[] binaryAESKey)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < binaryAESKey.length; i++)
          {
            sb.append(binaryAESKey[i]);
          }

        int from = 0, to = 8;
        String byte_of_key = new String();
        byte[] raw = new byte[aesKeyLen/8];
        String aes_key = sb.toString();
        for (int i = 0; i < aesKeyLen/8; i++)
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
        System.out.println("--Clifford Cocks Identity Based Cryptosystem for mail server (autonome version) --");
        System.out.println("");
        System.out.println("To run the program, type the following:");
        System.out.println("java -jar ibc.jar command [parameters]");
        System.out.println("List of available commands:");
        System.out.println("setup");
        System.out.println("keyextract");
        System.out.println("encrypt");
        System.out.println("decrypt");
        System.out.println(
                "Print --help to see the details information of the program usage");


    }

    static public void help()
    {   System.out.println("\n");
        System.out.println(
                "Please note: parameter order is irrelevant");
        System.out.println();
        System.out.println("------------------");
        System.out.println("About setup:");
        
        System.out.println(
                "Setup performs the initialization of Public Key Generator for domain and works with keystorage - "
                + "generate the necessary parameters for the cryptosystem, namely:");
        System.out.println(
                "-MasterPublicKey generation of a given length (parameter security)");
        System.out.println(
                "-MasterSecretKey generation of a given length (parameter security*2)");
        System.out.println("These settings are stored in keystorage (encrypted by AES on password, specified by the user)"
                + "(parameters -keystorage and -mpk)");
        System.out.println ("Otherwise, they are saved in the default directory");
        System.out.println();
        System.out.println("Usage:");
        System.out.println(
                "setup  -security 'positive integer' -mpk 'file_path' -keystorage 'path_to_keystorage' -domain 'domain-name (example@example.org)' -password 'root-pass-to-keystorage'");
        System.out.println("------------------");

        System.out.println("------------------");
        System.out.println("About keyextract:");
        
        System.out.println(
                "KeyExtract generates a secret key for encryption and signature for a user specified text identifier");
        System.out.println ("In this case, you must specify the path to the master public key system, generated by running setup (if you are running with the -mpk parameter)");
        System.out.println();
        System.out.println("Usage");
        System.out.println(
                "keyextract -keystorage 'path_to_keystorage' -password 'root-password-to-keystorage' -sk 'output_path_to_the_encryption_secret_key' -sks 'output_path_to_the_signing_secret_key'  -id 'e-mail adress'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About encrypt:");
        
        System.out.println(
                "encrypt makes encryption and signature (cryptocontainer) of a user-specified file");
        System.out.println("Usage:");
        System.out.println(
                "encrypt -to 'recipient-e-mail' -sks 'sender signing secret key' -mpk 'path_to_mpk'"
                + "-in 'path_to_the_file_for_encryption' -out 'output_path_to_the_encrypted_file'");
        System.out.println("------------------");
        System.out.println("------------------");
        System.out.println("About decrypt");
       
        System.out.println(
                "decrypt makes decryption and signature verification previously encrypted files");
        System.out.println("Usage:");
        System.out.println(
                "decrypt  -sk 'path-to-recipient-encryption-secret-key'"
                + "-in 'path_to_the_encrypted_file' -out 'output_path_to_the_decrypted_file' -from 'sender e-mail adress' -mpk 'path-to-mpk'");
        System.out.println("------------------");

    }

    static public void invalidParameters()
    {
        System.out.println(
                "Entered incorrect settings or missing required parameters, type --help for calling tips");
    }

    static public byte[] writeKeyData(BigInteger data)
    {
        return data.toByteArray();

    }

    static public BigInteger readKeyData(FileInputStream in) throws IOException
    {

        byte[] byteKey = new byte[in.available()];
        in.read(byteKey);
        return new BigInteger(byteKey);
        

    }
}
