/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.idbased.keymng;

/**
 *
 * @author foxneig
 */
public class Domain {
    private String domainName;
    private String MPK;
    private String MSK1;
    private String MSK2;
    private String checksumm1;
    private String checksumm2;

    public void set (String dn, String MPK, String MSK1, String MSK2, String checksumm1, String checksumm2) {
        this.domainName = dn;
        this.MPK = MPK;
        this.MSK1 = MSK1;
        this.MSK2 = MSK2;
        this.checksumm1 = checksumm1;
        this.checksumm2 = checksumm2;
    }
    public String getMPK () {
        return this.MPK;
    }
    public String getMSK1 () {
        return this.MSK1;
    }
    public String getMSK2 () {
        return this.MSK2;
    }
    public String getName () {
        return this.domainName;
    }
    public String getMSK1CheckSum () {
        return this.checksumm1;
    }
      public String getMSK2CheckSum () {
        return this.checksumm2;
    }

}
