package org.suai.idbased.crypto;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
public class Cryptocontainer {

    public int firstKeySize;
    public int secondKeySize;
    public int encryptedDataSize;
    public int signatureSize;
    public int dataSize;

    int writeParam(int dataSize, int firstKeySize, int secondKeySize,
                   int encryptedDataSize, int signatureSize)
    {
        if (dataSize < 0 || firstKeySize < 0 || secondKeySize < 0 || encryptedDataSize < 0 || signatureSize < 0)
          {
            return -1;
          }
        if (dataSize <= firstKeySize || dataSize <= secondKeySize || dataSize <= encryptedDataSize || dataSize <= signatureSize)
          {
            return -1;
          }

        this.dataSize = dataSize;
        this.firstKeySize = firstKeySize;
        this.secondKeySize = secondKeySize;
        this.encryptedDataSize = encryptedDataSize;
        this.signatureSize = signatureSize;
        return 0;



    }

    public Cryptocontainer getCryptocontainerParameters(FileInputStream fin,
                                                        DataInputStream ds)
            throws IOException
    {

        int data_size = fin.available();
        int key_size1 = ds.readInt();
        int key_size2 = ds.readInt();
        if (ds.available() < key_size1 + key_size2)
          {
            return null;
          }
        ds.skipBytes(key_size1 + key_size2);
        int encrypted_data_size = ds.readInt();
        int sign_length = data_size - key_size1 - key_size2 - encrypted_data_size - 12;
        int check = this.writeParam(data_size, key_size1, key_size2,
                encrypted_data_size, sign_length);
        if (check == -1)
          {
            return null;
          }
        return this;


    }
    public Cryptocontainer getCryptocontainerParameters(InputStream fin,
                                                        DataInputStream ds)
            throws IOException
    {

        int data_size = fin.available();
        int key_size1 = ds.readInt();
        int key_size2 = ds.readInt();
        if (ds.available() < key_size1 + key_size2)
          {
            return null;
          }
        ds.skipBytes(key_size1 + key_size2);
        int encrypted_data_size = ds.readInt();
        int sign_length = data_size - key_size1 - key_size2 - encrypted_data_size - 12;
        int check = this.writeParam(data_size, key_size1, key_size2,
                encrypted_data_size, sign_length);
        if (check == -1)
          {
            return null;
          }
        return this;


    }
}
