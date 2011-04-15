
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author foxneig
 */
public class DecryptException extends Exception{
    long s;
    long secret_key;
    long MPK;
    DecryptException (long s, long secret_key, long MPK) {
        this.s = s;
        this.secret_key = secret_key;
        this.MPK = MPK;
    }
    public void writeParam (PrintWriter fout) {
       
            fout.write("S+2r = " +this.s + " Secret Key = " +this.secret_key + " MPK = " + this.MPK + "\n");
       

    }


}
