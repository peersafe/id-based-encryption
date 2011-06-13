package org.suai.idbased.crypto;

import java.io.DataInputStream;
import java.io.IOException;

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

    public Cryptocontainer getCryptocontainerParameters(DataInputStream ds)
            throws IOException
    {

        int datasize = ds.available();
        int keySizeFirst = ds.readInt();
        int keySizeScnd = ds.readInt();
        if (ds.available() < keySizeFirst + keySizeScnd)
          {
            return null;
          }
        ds.skipBytes(keySizeFirst + keySizeScnd);
        int encrDataSize = ds.readInt();
        int signLen = datasize - keySizeFirst - keySizeScnd - encrDataSize - 12;
        int check = this.writeParam(datasize, keySizeFirst, keySizeScnd,
                encrDataSize, signLen);
        if (check == -1)
          {
            return null;
          }
        return this;


    }

}
