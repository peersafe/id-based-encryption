package org.suai.idbased;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
public class Cryptocontainer {

    int firstKeySize;
    int secondKeySize;
    int encryptedDataSize;
    int signatureSize;
    int dataSize;

    int writeParam(int dataSize, int firstKeySize, int secondKeySize, int encryptedDataSize, int signatureSize) {
        if (dataSize < 0 || firstKeySize < 0 || secondKeySize < 0 || encryptedDataSize < 0 || signatureSize < 0) {
            return -1;
        }
        if (dataSize <= firstKeySize || dataSize <= secondKeySize || dataSize <= encryptedDataSize || dataSize <= signatureSize) {
            return -1;
        }

        this.dataSize = dataSize;
        this.firstKeySize = firstKeySize;
        this.secondKeySize = secondKeySize;
        this.encryptedDataSize = encryptedDataSize;
        this.signatureSize = signatureSize;
        return 0;



    }
}
