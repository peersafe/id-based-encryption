
import java.util.Random;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author alex_neigum
 */
public class Client {
    long [] encrypt (int m, long PkID, long MPK) {
        int t;
        int  j;
        long s,s1;
        long inv_t;
        long[] ciphertext = new long[2];
       
        Random rand = new Random ();
        
        while (true) {
        t = (int) (rand.nextInt() % MPK);
        j = ResidueCalculation.Jacobi(t, MPK);
        //+1 = 1; -1 = 0
        if ( m == 0 && j == -1) {
           inv_t =  ResidueCalculation.inv(t, MPK);
           ciphertext[0] = (t + PkID*inv_t)%MPK;
           ciphertext[1] =(t - PkID*inv_t)%MPK;
           if (ciphertext[1] < 0) ciphertext[1] = MPK + ciphertext[1];
           
            return ciphertext;
        }
 else
     if ( m == 1 && j == 1) {
         inv_t =  ResidueCalculation.inv(t, MPK);
         ciphertext[0] = (t + PkID*inv_t)%MPK;
         ciphertext[1] =(t - PkID*inv_t)%MPK;
         if (ciphertext[1] < 0) ciphertext[1] = MPK + ciphertext[1];
        
         return ciphertext;

     }
        }
    }
    int decrypt (long c, long SkID, long MPK) {
       
        int Jacobi = ResidueCalculation.Jacobi((c + 2 * SkID)%MPK, MPK);
       
        if (Jacobi == 1)
            return 1;
        else
            if (Jacobi == -1)
                return 0;
            else {
                return -1; // error



    }

}
}
