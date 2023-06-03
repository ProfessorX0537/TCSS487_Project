package com.company;

import java.math.BigInteger;
import java.util.Arrays;

public class ECArithmetic {
    private static final BigInteger p = new BigInteger("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439");
    private static final BigInteger r = new BigInteger("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779");

    private static BigInteger b = new BigInteger("8");
    private static BigInteger c = new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258");

    public static void main(String[] args) {
        Point G = new Point(b,c);
        Point P2 = new Point(BigInteger.valueOf(4), BigInteger.valueOf(8));
        Point scaled = exponentiation(G, new BigInteger("4"));
     //   Point added = add(G, G);
        System.out.println("Scaled point X: " + scaled.getPx() + "\nScaled point Y: " + scaled.getPy());

        System.out.println("Length of Y " + c.toByteArray().length);
        System.out.println("Raw Y " + Arrays.toString(c.toByteArray()));
        System.out.println("BigInteger " + c);
        System.out.println("Y decoded from Px " + Arrays.toString(toByteArrayLittleEndian(decode(b, false).getPy())));
        System.out.println("BigInteger " + decode(b, false).getPy());
        System.out.println("P1 encoded " + Arrays.toString(encode(G).toByteArray()));
        System.out.println("BigInteger " + encode(G));
        System.out.println("P: " + p);
    }

    /**
     * Takes a point and encodes per specification. Y in little-endian with most significant octet as zero.
     * Then place the least significant byte from X into most significant byte of Y.
     * @param P The given point on ed448 curve
     * @return BigInteger representation of encoded point
     */
    public static BigInteger encode(Point P) {
        byte[] encoded = toByteArrayLittleEndian(P.getPy());
        byte[] x = toByteArrayLittleEndian(P.getPx());
        encoded[encoded.length -1] = x[0];
        return new BigInteger(encoded);
    }


    /**
     * Given BigInteger x from a point (x,y) and the least significant bit of y. Decode the
     * BigInteger y.
     * @param x coordinate of a point on ed448
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return the decoded point
     */
    public static Point decode(BigInteger x, boolean lsb) {
        //TODO not checking actual bit may cause a problem
        BigInteger inverse = (BigInteger.ONE.add(new BigInteger("39081").multiply(x.pow(2)))).modInverse(p);
        BigInteger radicand = (BigInteger.ONE.subtract(x.pow(2))).multiply(inverse);

        return new Point(x,computeSqrt(radicand, p, lsb));
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

    /**
     * Performs scalar multiplication
     * @param P The point to be scaled
     * @param s The scalar
     * @return Scaled point
     */
    public static Point exponentiation(Point P, BigInteger s) {
        String bin = s.toString(2);
        if(s.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ONE);
        } else if(bin.length() == 1) {
            return P;
        } else {
            Point G = P;
            for (int i = 1 ; i < bin.length(); i++) {
                G = add(G, G);
                if (bin.charAt(i) == '1') {
                    G = add(G, P);
                }
            }
            return G;
        }
    }


    /**
     * Performs Edwards addition on 2 points
     * @param P1
     * @param P2
     * @return a point that is the sum of two given points
     */
    public static Point add(Point P1, Point P2) {
        BigInteger one = BigInteger.ONE;
        BigInteger d = BigInteger.valueOf(-39081);

        BigInteger PX3Bottom = one.add(d.multiply(P1.getPx()).multiply(P2.getPx()).multiply(P1.getPy()).multiply(P2.getPy()));
        BigInteger PX3Top = (((P1.getPx().multiply(P2.getPy())).add(P1.getPy().multiply(P2.getPx()))));
        BigInteger PY3Top = (((P1.getPy().multiply(P2.getPy())).subtract(P1.getPx().multiply(P2.getPx()))));
        BigInteger PY3Bottom = one.subtract(d.multiply(P1.getPx().multiply(P2.getPx()).multiply(P1.getPy()).multiply(P2.getPy())));

        //don't do normal division in different modulus
        return new Point(PX3Top.multiply(PX3Bottom.modInverse(p)).mod(p), PY3Top.multiply(PY3Bottom.modInverse(p)).mod(p));
    }

    /**
     * reverses the order of a byte[] ie convert into little endian
     * https://stackoverflow.com/questions/12893758/how-to-reverse-the-byte-array-in-java
     * @param b
     * @return
     */
    public static byte[] toByteArrayLittleEndian(BigInteger b) {
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

    /************************************************************
     *                        Generators                        *
     ************************************************************/
    //Constructor for the neutral element
    public static Point neutralElement() {
        return new Point(BigInteger.ZERO, BigInteger.ONE);
    }

    //a constructor for a curve point given its x and y cords
    public static Point curve(BigInteger x, BigInteger y) {
        return new Point(x, y);
    }

    //constructor for a curve point from its x cords and the least significant bit of y
    public static Point curveLeastSig(BigInteger x) {
        return decode(x, false);
    }

    /************************************************************
     *                         Getters                          *
     ************************************************************/

    public static BigInteger getR() {
        return r;
    }

    public static  BigInteger getP() {
        return p;
    }
}
