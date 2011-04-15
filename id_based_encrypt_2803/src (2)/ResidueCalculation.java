/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author alex_neigum
 */
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.Random;

public class ResidueCalculation {

    static long inv (long a, long N) { //возвращает обратный к а по модулю N
        long [] coeffs = new long[2];
        if (euclidex(a,N,coeffs) != 1)
            return -1;
        if (coeffs[0]<0) coeffs[0] = N+coeffs[0];
        else
            if (coeffs[0]<-N) coeffs[0] = 2*N+coeffs[0];
       
        return coeffs[0];


    }
//    static int Jacobi (long a, long N) { //возвращает true, если символ Якоби (a/n) = 1, false - в иных случаях
// /* 1 (проверка взаимной простоты). Если НОД (a, b)≠1, выход из алгоритма с ответом 0.
//
//2 (инициализация). r:=1
//
//3 (переход к положительным числам).
// Если a<0 то
//  a:=-a
//  Если b mod 4 = 3 то r:=-r
// Конец если
//
//4 (избавление от чётности). t:=0
// Цикл ПОКА a – чётное
//  t:=t+1
//  a:=a/2
// Конец цикла
// Если t – нечётное, то
//  Если b mod 8 = 3 или 5, то r:=-r.
// Конец если
//
//5 (квадратичный закон взаимности). Если a mod 4 = b mod 4 = 3, то r:=-r.
//  c:=a; a:=b mod c; b:=c.
//
//6 (выход из алгоритма?). Если a≠0, то идти на шаг 4, иначе выйти из алгоритма с ответом r
//      * */
//long [] coeffs = new long[2];
//long c = 0;
//        if (euclidex(a,N,coeffs) != 1) {
//          return 0;
//        }
//      int r = 1;
//      if ( a < 0) {
//          a = -a;
//          if (N%4 == 3)
//              r = -r;
//        }
//      int t = 0;
//      while (a!=0) {
//      while (a%2 == 0) {
//          t++;
//          a/=2;
//      }
//      if (t%2!=0) {
//          if (N%8 == 3 || N%8 == 5) {
//              r = -r;
//          }
//      }
//      if (a%4 ==3 && N%4 == 3) r = -r;
//      c = a;
//      a = N%c;
//      N = c;
//        }
//      return r;
//
//
//    }
    static int Jacobi (long a, long b) {
        long coeffs [] = new long [2];
        int e = 0;
        int s = 1;
        if (a == 0) return 0;
        if (a == 1) return 1;
        if (euclidex(a,b,coeffs)!=1) return 0;
        while (a%2 == 0) {
            e++;
            a/=2;
        }
        if (e%2 == 0) s = 1;
        else
        {
            if (b%8 == 1 || b%8 == 7) s = 1;
            else
                if (b%8 == 3 || b%8 == 5) s = -1;
        }
        if (b%4 == 3 && a%4 == 3) s = -s;
        b = b%a;
        if (a == 1) return s;
        else
            return s*Jacobi(b,a);




    }
    static long powmod (long a, long p, long N) { //возвращает a^p mod N
  long b=1;
  while (p!=0) {
      if (p%2!=0) {
          //b = (b*a)%N;
          b = b%N * a%N;
          p--;
  }
      p/=2;
   //   a = (a*a)%N;
      a = a%N * a%N;
    }
  return b;
    }
    static long euclidex (long a, long b, long []coeffs) { //рассширенный алгоритм Евклида
    //coeffs[0] = x; coeffs[1] = y;
    /*
НА ВХОДЕ: два неотрицательных числа a и b: a>=b
НА ВЫХОДЕ: d=НОД(a,b) и целые x,y: ax + by = d.

1. Если b=0 положить d:=a, x:=1, y:=0 и возвратить (d,x,y)
2. Положить x2:=1, x1:=0, y2:=0, y1:=1
3. Пока b>0
    3.1 q:=[a/b], r:=a-qb, x:=x2-qx1, y:=y2-qy1
    3.2 a:=b, b:=r, x2:=x1, x1:=x, y2:=y1, y1:=y
4. Положить d:=a, x:=x2, y:=y2 и возвратить (d,x,y)
     */
    long q, r, x1, x2, y1, y2,d;
    if (b == 0)
	{
		d = a; coeffs[0] = 1; coeffs[1] = 0;
		return d;
	}

	x2 = 1; x1 = 0; y2 = 0; y1 = 1;
        while (b > 0)
	{
		q = a / b; r = a - q * b;
		coeffs[0] = x2 - q * x1; coeffs[1] = y2 - q * y1;
		a = b; b = r;
		x2 = x1; x1 = coeffs[0]; y2 = y1; y1 = coeffs[1];
        }
        d = a; coeffs[0] = x2; coeffs[1] = y2;
        return d;
    }


    static long genPrime (int security) { //генерация простого числа
    Random rand = new Random();
    double size = Math.pow (2,security - 2);
    boolean isPrime = false;
    int p;
    int nround;
    do {
    p = 4*rand.nextInt((int) (size))+3; //генерим число вида 3mod4
    nround = (int) (Math.log10(p) / Math.log10(2)); //число раундов log2(p);
    isPrime = RabinMillerTest(p,nround);
    }
    while (isPrime!=true);
    return p;

    }
   static boolean RabinMillerTest (long n, int nround) {
    if (n == 2) return true;
    if (n%2 == 0) return false;
    if (n == 1) return true;
    Random rand = new Random();
    long p = 0;
    long s = 0;
    int a = 0;
    long x = 0;
    boolean isPrime = false;
    p = n - 1;

    /*
    Тест Миллера-Рабина (n, a)                  // n —  число; a —  основание
{
  Find m and k such that n–1 = m × 2k
  T  am mod n
  if ( T = ±1) return "a prime"
  for (I  1 to k–1)                            // k–1 — максимальное число шагов
 {
   T  T2 mod n
   if (T = +1) return "a composite"            // составное
   if (T = –1) return "a prime"                // простое
 }
return "a composite"
     */
    while ((p%2) == 0) {
        s++;
        p/=2;
    }
label:    for (int i = 0; i < nround; i++) {
      a = rand.nextInt((int)n-2);
      if (a<2) a = (int) ((a + 2) % (n - 2));
      x =   (int) powmod(a,p,n);
      if (x == 1 || x == n-1) {
        isPrime = true;
        continue;
        }
      for (int j = 0; j < s - 1; j++) {
          x =   (int) powmod (x,2,n);
          if (x == 1) {
              isPrime = false ;
              return isPrime;
          }
          if (x == n-1) {
          isPrime = true;
          i++;
          break label;
          }

      }
      return false;
    }
    return isPrime;
  }
   static long euler (long p, long q) {
       return (p-1)*(q-1);
   }
   public static void main_ (String args []) {
       System.out.println (""+powmod(-2,700521295,172932797));
   }

  
    } 

