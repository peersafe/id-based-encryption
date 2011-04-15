/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author alex_neigum
 */
public class PKG {

    long MPK;
    long MSK;
    long P, Q;
    int security;
    long e = 65537;
    long d;
    long SSK;


    PKG(int size) {
        security = size;
    }

    void setup() { // генерация M = P*Q

        // генерим P
        while (true) {
            P = ResidueCalculation.genPrime(security);
            Q = ResidueCalculation.genPrime(security);
            if (P != Q) {
                break;
            }
        }
        MPK = P * Q;
    }

    static long genPkID(String id, long P, long Q, long MPK) {
        int i = 0;
        long a = 0;
        int j = 0;
        int k = 0;
        a = id.hashCode() % 32;
        while (true) {
            j = ResidueCalculation.Jacobi(a, P);
            //   System.out.println ("Jacobi("+a+","+P+")= "+ j);
            k = ResidueCalculation.Jacobi(a, Q);
            //   System.out.println ("Jacobi("+a+","+Q+")= "+ k);
            if (j == -1 && k == -1) {
                return (MPK - a);
            } else if (j == 1 && k == 1) {
                return a;
            } else {
                a++;
            }
        }
    }

    long keyExtract(String id) {  //генерация секретного ключа id

        long a = genPkID(id, P, Q, MPK);

        long exp = (MPK + 5 - (P + Q)) / 8;

        MSK = ResidueCalculation.powmod(a, exp, MPK);


        return MSK;

    }
    void getSecretExponent () {
        long phi = ResidueCalculation.euler(P, Q);
        this.d =  ResidueCalculation.inv(this.e, phi);
    }
    long signKeyExtract (String id) {
        int _id = Math.abs(id.hashCode()%32);
        SSK = ResidueCalculation.powmod(_id, d, MPK);
        return SSK;


    }

}
