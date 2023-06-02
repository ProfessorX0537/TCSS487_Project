package com.company;

import java.math.BigInteger;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class ECArithmetic {

    private static BigInteger b = new BigInteger("409366642661545609548304506451761004424499037950672891330661617237156207698394905026410173085555315488943712774203132690300784549962144");

    public static void main(String[] args) {
        Point P1 = new Point(BigInteger.valueOf(2), BigInteger.valueOf(4));
        Point P2 = new Point(BigInteger.valueOf(4), BigInteger.valueOf(8));
        Point P3 = add(P1, P2);
        String s = "409366642661545609548304506451761004424499037950672891330661617237156207698394905026410173085555315488943712774203132690300784549962144";
        System.out.println(s.length());
        System.out.println(b.toByteArray().length);
        System.out.println(Arrays.toString(b.toByteArray()));
        System.out.println(Arrays.toString(toByteArray(b)));
    }

    //Constructor for the neutral element
    public ECArithmetic() {

    }

    //a constructor for a curve point given its x and y cords
    public ECArithmetic(BigInteger x, BigInteger y) {

    }

    //constructor for a curve point from its x cords and the least significant bit of y
    public ECArithmetic(BigInteger x) {

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
        System.out.println("PX3 " + PX3);
        System.out.println("PY3 " + PY3);
        System.out.println("PX3 Bottom " + PX3Bottom);
        System.out.println("PY3 Bottom " + PY3Bottom);
        Point summedPoint = new Point(PX3.divide(PX3Bottom), PY3.divide(PY3Bottom));
        System.out.println("New x: " + summedPoint.getPx());
        System.out.println("New y: " + summedPoint.getPy());
        return summedPoint;
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
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
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
