package org.suai.idbased;

import org.suai.idbased.Sign;
import org.suai.idbased.ResidueCalculation;
import org.suai.idbased.DecryptException;
import org.suai.idbased.Cryptocontainer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author alex_neigum
 */
public class Util {

    static byte [] KeyToBinary(byte[] raw) {
        StringBuffer sb = new StringBuffer();
        byte [] binaryKey;
        for (int i = 0; i < raw.length; i++) {
            String binary = null;
            binary = Integer.toBinaryString(raw[i] & 0xff);
            if (binary.length() < 8) {
                for (int k = 0; k < 8 - binary.length(); k++) {
                    sb.append("0");
                }
            }
            sb.append(binary);

        }
        binaryKey = new byte [sb.length()];
        for (int i = 0; i< sb.length(); i++)
            binaryKey[i] = sb.charAt(i) == '0'? (byte) 0: (byte) 1;
        return binaryKey;

    }
    static void GetEncryptedKey(DataInputStream din, boolean keytype, Cryptocontainer cc, BigInteger[] encrypted_aes_key) throws IOException {
        int size_of_encr_keybyte;
        din.skipBytes(8);
        if (keytype == false) {
            for (int i = 0; i < 128; i++) {
                size_of_encr_keybyte = din.readInt();

                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);


            }
            din.skipBytes(cc.secondKeySize);
        } else {
            din.skipBytes(cc.firstKeySize);
            for (int i = 0; i < 128; i++) {
                size_of_encr_keybyte = din.readInt();
                byte[] buff = new byte[size_of_encr_keybyte];
                din.read(buff);
                encrypted_aes_key[i] = new BigInteger(buff);

            }
        }
    }

    static byte[] BinaryToByteKey(int[] binary_aes_key) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < binary_aes_key.length; i++) {
            sb.append(binary_aes_key[i]);
        }

        int from = 0, to = 8;
        String byte_of_key = new String();
        byte[] raw = new byte[16];
        String aes_key = sb.toString();
        for (int i = 0; i < 16; i++) {
            byte_of_key = aes_key.substring(from, to);


            raw[i] = Integer.valueOf(byte_of_key, 2).byteValue();
            from = to;
            to = to + 8;
        }
        return raw;
    }
    static void usage () {
        System.out.println ("Для запуска программы напечатайте следующее:");
        System.out.println ("id_based_encrypt.jar команда [параметры]");
        System.out.println ("Список доступных команд:");
        System.out.println ("setup");
        System.out.println ("keyextract");
        System.out.println ("encrypt");
        System.out.println ("decrypt");
        System.out.println ("sign");
        System.out.println ("verify");
        System.out.println ("Run with --help to see advanced command help information");


    }
    static void help () {
        System.out.println ("Информация о команде setup:");
        System.out.println ("------------------");
        System.out.println ("Setup выполняет начальную инициализацию Public Key Generator - "
                +"генерацию необходимых параметров для работы криптосистемы, а именно:");
        System.out.println  ("-генерация MasterPublicKey заданной длины (параметр security)");
        System.out.println ("-генерация MasterSecretKey заданной длины (параметр security)");
        System.out.println ("При необходимости данные параметры сохраняются в файлы, указанный пользователем"
                +"(параметры -msk и -mpk");
        System.out.println ();
        System.out.println ("Использование:");
        System.out.println ("setup  -security 'целое_положительное_число' [-mpk 'путь_к_файлу'] [-msk 'путь_к_файлу']");
        System.out.println ("------------------");


        System.out.println ("Информация о команде keyextract:");
        System.out.println ("------------------");
        System.out.println ("KeyExtract генерирует секретный ключ шифрования для пользователя с заданным текстовым идентификатором");
        System.out.println ();
        System.out.println ("Использование:");
        System.out.println ("keyextract [-mpk 'путь_к_файлу_с_публичным_ключом_системы]'-sk 'путь_к_файлу_с_cекретному_ключу'  -id 'адрес e-mail'");
        System.out.println ("------------------");

        System.out.println ("Информация о команде encrypt:");
        System.out.println ("------------------");
        System.out.println ("encrypt производит шифрование заданного пользователем файла");
        System.out.println ("Использование:");
        System.out.println ("encrypt [-mpk 'путь_к_файлу_с_открытым_ключом системы'] -id 'адрес e-mail'"+
                "-in 'путь_к_файлу_для_шифрования' -out 'путь_к_зашифрованному_файлу'");
        System.out.println ("------------------");

        System.out.println ("Информация о команде decrypt");
        System.out.println ("------------------");
        System.out.println ("decrypt производит дешифрование ранее зашифрованного файла");
        System.out.println ("Использование:");
        System.out.println ("decrypt [-mpk 'путь_к_файлу_с_открытым_ключом системы'] [-sk 'путь_к_файлу_с_секретным_ключом']"+
                "-in 'путь_к_зашифрованному_файлу' -out 'путь_к_дешифрованному_файлу'");
        System.out.println ("------------------");

        System.out.println ("Информация о команде sign");
        System.out.println ("------------------");
        System.out.println ("sign производит подпись заданного пользователем файла");
        System.out.println ("Использование:");
        System.out.println ("sign  [-mpk 'путь_к_файлу_с_публичным_ключом'] -sk 'путь_к_файлу_с_секретным_ключом_для_подписи' или -id 'адрес_e-mail' -out 'путь_к_файлу_с_подпиcью");
        System.out.println ("------------------");

        System.out.println ("Информация о команде verify");
        System.out.println ("------------------");
        System.out.println ("verify производит проверку подписи и возвращает результат проверки");
        System.out.println ("Использование:");
        System.out.println ("verify [-mpk 'путь_к_файлу_с_публичным_ключом'] -in 'путь_к_файлу_с_подписью' ");
        System.out.println ("------------------");
    }
    static void invalidParameters () {
        System.out.println ("Введены неправильные параметры, напечатайте --help для вызова подсказки");
    }
    
    static byte[] writeKeyData (BigInteger data) {
//        BASE64Encoder enc = new BASE64Encoder();
//
//        String encoded = enc.encode(data.toByteArray());

        return data.toByteArray();

    }
    static BigInteger readKeyData (FileInputStream in) throws IOException {
//        BASE64Decoder dec = new BASE64Decoder ();
//        BigInteger key = new BigInteger(dec.decodeBufferToByteBuffer(in).array());
        int length = in.available();
        byte [] byte_key = new byte [length];
        in.read(byte_key);
        BigInteger key = new BigInteger (byte_key);
        return key;

    }

}
