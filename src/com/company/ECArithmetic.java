package com.company;

import java.math.BigInteger;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class ECArithmetic {
    private static final BigInteger p = new BigInteger("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439");

    private static BigInteger b = new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258");

    public static void main(String[] args) {
        Point P1 = new Point(new BigInteger("8"),new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258"));
        Point P2 = new Point(BigInteger.valueOf(4), BigInteger.valueOf(8));
        Point P3 = add(P1, P2);
        byte c = 50; //least significant byte of y
        System.out.println("Length of Y " + b.toByteArray().length);
        System.out.println("Raw Y " + Arrays.toString(b.toByteArray()));
        System.out.println("Y decoded from Px " + Arrays.toString(toByteArray(decode(new BigInteger("8"), c))));
        System.out.println("P1 encoded " + Arrays.toString(encode(P1)));
        System.out.println("P: " + p);
    }

    //Constructor for the neutral element
    public ECArithmetic() {

    }

    //a constructor for a curve point given its x and y cords
    public ECArithmetic(BigInteger x, BigInteger y) {

    }

    //constructor for a curve point from its x cords and the least significant bit of y
    public ECArithmetic(BigInteger x, byte leastY) {
    }

    // method to compare points for equality
    public static boolean compare(Point P1, Point P2) {
        return (P1.getPx().compareTo(P2.getPx()) == 0) && (P1.getPy().compareTo(P2.getPy()) == 0);
    }

    // method to obtain the opposite of a point
    public static Point opposite(Point P) {
        P.setPx(P.getPx().multiply(BigInteger.valueOf(-1)));
        return P;
    }

    // method to compute the sum of the current point and another point
    public static Point add(Point P1, Point P2) {
        BigInteger one = BigInteger.ONE;
        BigInteger d = BigInteger.valueOf(-39081);
        BigInteger PX3Bottom = one.add(d.multiply(P1.getPx()).multiply(P2.getPx()).multiply(P1.getPy().multiply(P2.getPy())));
        BigInteger PX3 = (((P1.getPx().multiply(P2.getPy())).add(P1.getPy().multiply(P2.getPx()))));
        BigInteger PY3 = (((P1.getPy().multiply(P2.getPy())).subtract(P1.getPx().multiply(P2.getPx()))));
        BigInteger PY3Bottom = one.subtract(d.multiply(P1.getPx().multiply(P2.getPx()).multiply(P1.getPy()).multiply(P2.getPy())));
//        System.out.println("PX3 " + PX3);
//        System.out.println("PY3 " + PY3);
//        System.out.println("PX3 Bottom " + PX3Bottom);
//        System.out.println("PY3 Bottom " + PY3Bottom);
        Point summedPoint = new Point(PX3.divide(PX3Bottom), PY3.divide(PY3Bottom));
//        System.out.println("New x: " + summedPoint.getPx());
//        System.out.println("New y: " + summedPoint.getPy());
        return summedPoint;
    }

    public static byte[] encode(Point P) {
        byte[] encoded = toByteArray(P.getPy());
        byte[] x = toByteArray(P.getPx());
        encoded[encoded.length -1] = x[0];
        return encoded;
    }

    /**
     * takes Px and decodes Py
     * @param x
     * @param leastY
     * @return
     */
    public static BigInteger decode(BigInteger x, byte leastY) {
        //what to do with least significant byte of y?
        BigInteger inverse = (BigInteger.ONE.add(new BigInteger("39081").multiply(x.pow(2)))).modInverse(p);
        BigInteger radicand = (BigInteger.ONE.subtract(x.pow(2))).multiply(inverse);
        return computeSqrt(radicand, p, false);
    }

    //method that can perform scalar multiplication
    // exponentiation algorithm in course slides

    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/

    /**
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger computeSqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public static Point exponentiation(Point P, BigInteger s) {
        Point V = P;
        for (BigInteger i = s.subtract(BigInteger.ONE); i.compareTo(BigInteger.ZERO) > -1; i = i.subtract(BigInteger.ONE)) {
            V = add(V, V);
            if (s.testBit(i.intValue())) {
                V = add(V, P);
            }
        }
        return V;
    }

    //need to convert cords into little endian string of 57 octets with most significant octet is always zero

    /**
     * reverses the order of a byte[] ie convert into little endian
     * https://stackoverflow.com/questions/12893758/how-to-reverse-the-byte-array-in-java
     * @param b
     * @return
     */
    public static byte[] toByteArray(BigInteger b) {
        byte[] s = b.toByteArray();
        int i = 0;
        int j = s.length -1;
        byte temp;
        while (j > i) {
            temp = s[j];
            s[j] = s[i];
            s[i] = temp;
            j--;
            i++;
        }
        return s;
    }

    /**
     * Inner class to hold values of points
     * @author Xavier Hines
     */
    private static class Point {
        private BigInteger Px;
        private BigInteger Py;

        public Point(BigInteger Px, BigInteger Py) {
            this.Px = Px;
            this.Py = Py;
        }

        public BigInteger getPx() { return Px; }

        public BigInteger getPy() { return Py; }

        public void setPx(BigInteger thePx) { this.Px = thePx; }

        public void setPy(BigInteger thePy) { this.Py = thePy; }

        @Override
        public String toString() {
            String s = "";
            s = s + "X: " +Px.toString() + " Y:"+ Py.toString();
            return s;
        }
    }

}
