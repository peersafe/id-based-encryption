
import java.util.Random;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author alex_neigum
 */
public class Util {
    static long genPkID (String id, long MPK) {
        int i = 0;
        long a = 0;
        int j = 0;
        int k = 0;
        a = id.hashCode()%32;
        while (true) {
        j = ResidueCalculation.Jacobi(a, MPK);
     //   System.out.println ("Jacobi("+a+","+P+")= "+ j);
       
     //   System.out.println ("Jacobi("+a+","+Q+")= "+ k);
        if (j == 1) return a;
            else
                a++;
        }
        }





}

