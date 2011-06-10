package org.suai.idbased.util;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author alex_neigum
 */
import java.math.BigInteger;

public class ResidueCalculation {
        static private BigInteger two = BigInteger.valueOf(2);
        static private BigInteger tree = BigInteger.valueOf(3);
        static private BigInteger four = BigInteger.valueOf(4);
        static private BigInteger five = BigInteger.valueOf(5);
        static private BigInteger eight = BigInteger.valueOf(8);

//    static int Jacobi (BigInteger a, BigInteger b) {
//        int e = 0;
//        int s = 1;
//        BigInteger two = BigInteger.valueOf(2);
//        BigInteger tree = BigInteger.valueOf(3);
//        BigInteger four = BigInteger.valueOf(4);
//        BigInteger five = BigInteger.valueOf(5);
//        BigInteger seven = BigInteger.valueOf(7);
//        BigInteger eight = BigInteger.valueOf(8);
//
//
//
//
//
//        if (a.compareTo(BigInteger.ZERO)== 0) {
//
//            return 0;
//        }
//        if (a.compareTo(BigInteger.ONE) == 0 ){
//
//            return 1;
//        }
//
//        if (a.gcd(b).compareTo(BigInteger.ONE)!=0) {
//
//            return 0;
//        }
//        while (a.mod(two).compareTo(BigInteger.ZERO) == 0) {
//            e++;
//            a = a.divide(two);
//
//        }
//
//        if (e%2 == 0) s = 1;
//        else
//        {
//            if (b.mod(eight).compareTo(BigInteger.ONE) == 0 || b.mod(eight).compareTo(seven) == 0)
//                s = 1;
//            else
//                if ((b.mod(eight).compareTo(tree) == 0 || b.mod(eight).compareTo(five) == 0))
//                    s = -1;
//        }
//
//        if ((b.mod(four).compareTo(tree) == 0 && a.mod(four).compareTo(tree) == 0)) s = -s;
//        b = b.mod(a);
//        if (a.compareTo(BigInteger.ONE) == 0) {
//        //    System.out.print (s+"\n");
//            return s;
//        }
//        else
//            return s*Jacobi(b,a);
//
//
//
//
//    }
    static public int Jacobi(BigInteger a, BigInteger b)
    {
        int sign = 1;
        BigInteger t;
    

        if (a.compareTo(BigInteger.ZERO) == 0)
          {
            return 0;
          }
        if (a.compareTo(BigInteger.ONE) == 0)
          {
            return 1;
          }
//        if (a.gcd(b).compareTo(BigInteger.ONE) != 0)
//          {
//            return 0;
//          }
        while (a.compareTo(BigInteger.ONE) == 1)
          {
            if (a.mod(four).compareTo(BigInteger.ZERO) == 0)
              {
                a = a.divide(four);
              }
            else if (a.mod(two).compareTo(BigInteger.ZERO) == 0)
              {
                if (b.mod(eight).compareTo(tree) == 0 || b.mod(eight).compareTo(
                        five) == 0)
                  {
                    sign = -sign;
                  }
                a = a.divide(two);
              }
            else
              {
                if (a.mod(four).compareTo(tree) == 0 && b.mod(four).compareTo(
                        tree) == 0)
                  {
                    sign = -sign;
                  }
                t = a;
                a = b.mod(a);
                b = t;



              }

          }

        return sign;



    }

    static public BigInteger euler(BigInteger p, BigInteger q)
    {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static void main_(String args[])
    {
    }
}
