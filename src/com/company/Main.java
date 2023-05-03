package com.company;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Main class of NIST compliant implementation of KMACX0F256
 * Takes inspiration from majossarinen's C implementation which can be found here
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * @author Xavier Hines
 * @author Cage Peterson
 * @author Thomas Brookes
 */
public class Main {
    /************************************************************
     *                Keccak-f Sponge Construction              *
     ************************************************************/

    /**
     * byte[] which is the width of the Keccak-f sponge (1600 bits) where each
     * lane in the sponge is a 64 bit word. There are 25 lanes which makes a
     *  64 * 5 * 5 three-dimensional matrix which Keccak-f permutations will be
     *  performed on.
     */
    private byte[] b = new byte[200];

    /**
     * The number of rounds performed in Keccak-f
     */
    private final int keccakfRnds = 24;

    /**
     * Value used to initialize SHA3
     */
    private final int SHAKE256 = 32;

    /**
     * Values used in multiple methods
     */
    private int pt, rsiz, mdlen;


    /**
     * The round constants defined by specification of which there are 24
     */
    private final long[] keccakfRndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Rotation offsets for the roh function.
     */
    private final int[] keccakfRotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * The position for each word with respect to lane shifts in pi function
     */
    private  final int[] keccakfPilane = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * Will perform some bit rotation on a given lane
     * @param x lane
     * @param y amount of rotation
     * @return the lane rotated
     */
    private static long rotLane64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    private void sha3Keccakf(byte[] v) {
        long[] bc = new long[5];
        long[] st = new long[25];
        long t;

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            st[i] = (((long)v[j + 0] & 0xFFL)      ) | (((long)v[j + 1] & 0xFFL) <<  8) |
                    (((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
                    (((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
                    (((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
        }

        // actual iteration
        for (int r = 0; r < keccakfRnds; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ rotLane64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    st[j + i] ^= t;
            }

            // Rho Pi
            t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakfPilane[i];
                bc[0] = st[j];
                st[j] = rotLane64(t, keccakfRotc[i]);
                t = bc[0];
            }

            //  Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++)
                    bc[i] = st[j + i];
                for (int i = 0; i < 5; i++)
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            //  Iota
            st[0] ^= keccakfRndc[r];
        }

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j+=8) {
            t = st[i];
            v[0 + j] = (byte) (t & 0xFF);
            v[1 + j] = (byte) ((t >> 8) & 0xFF);
            v[2 + j] = (byte) ((t >> 16) & 0xFF);
            v[3 + j] = (byte) ((t >> 24) & 0xFF);
            v[4 + j] = (byte) ((t >> 32) & 0xFF);
            v[5 + j] = (byte) ((t >> 40) & 0xFF);
            v[6 + j] = (byte) ((t >> 48) & 0xFF);
            v[7 + j] = (byte) ((t >> 56) & 0xFF);
        }
    }





    /************************************************************
     *                    Auxiliary Methods                     *
     ************************************************************/


    /**
     * Encodes a BigInteger into a byte[] representation then reverses all the bits and appends the
     * reversed byte representation of n.
     * @param x a Biginteger to be right encoded
     * @return returns a byte[] representation of the BigInteger after encoding
     */
    private static byte[] rightEncode(BigInteger x) {
        //TODO : everything is signed in java naturally, does this impact my base256?

        //Validity Condition: 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        // 1. let n be the smallest positive int for which 2^8n > x
        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }
        System.out.println("value of n in right encode: " + n);
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x. That is to say that the byte
        // representation of x
        byte[] xBytes = x.toByteArray();
        // handles exception where first byte is zero because of java signed numbers
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }
        // 3. let xBytes = enc8(xi) for i = 1 to n. That is reverse the order of each byte
        // so that the lower order bit is at position 0. Then reverse order of bytes
        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i+1)] = xBytes[i];
        }
        // 4. let xBytes.length + 1 = enc8(n). That is appended the reversed byte representation
        // of n to the end of xBytes.
        output[output.length-1] = reverseBitsByte((byte)n);
        return output;
    }

    /**
     * Encodes a BigInteger into a byte[] representation then reverses all the bits and appends the
     * reversed byte representation of n to the beginning of byte[].
     * @param x a Biginteger to be right encoded
     * @return returns a byte[] representation of the BigInteger after encoding
     */
    private static byte[] leftEncode(BigInteger x) {
        //TODO : everything is signed in java naturally, does this impact my base256?

        //Validity Condition: 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        // 1. let n be the smallest positive int for which 2^8n > x
        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }
        System.out.println("value of n in left encode: " + n);
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x. That is to say that the byte
        // representation of x
        byte[] xBytes = x.toByteArray();
        // handles exception where first byte is zero because of java signed numbers
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }
        // 3. let xBytes = enc8(xi) for i = 1 to n. That is reverse the order of each byte
        // so that the lower order bit is at position 0. Then reverse order of bytes
        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i)] = xBytes[i];
        }
        // 4. let xBytes.length + 1 = enc8(n). That is appended the reversed byte representation
        // of n to the end of xBytes.
        output[0] = reverseBitsByte((byte)n);
        return output;
    }

    /**
     * Encodes a byte[] that represents a string of bits so that it can be unambiguously
     * parsed from the beginning of S.
     * @param S byte oriented string of bits
     * @return encoded bit string S
     */
    private static byte[] encodeString(byte[] S) {
        if (S == null || S.length == 0) {
            return leftEncode(BigInteger.ZERO);
        } else {
            //If S were not byte oriented then the S.length would need to be made a
            //multiple of 8 i.e. (S.length << 3)
            return concat(leftEncode(new BigInteger(String.valueOf(S.length))), S);
        }
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @author Paulo Barreto
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    private static byte[] bytepad(byte[] X, int w) {
        //TODO w may need to become a biginteger

        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || x.
        byte[] wEncode = leftEncode(BigInteger.valueOf(w));
        // NB: z.length is the smallest multiple of w that fits wEncode.length + X.length
        byte[] z = new byte[w * ((wEncode.length + X.length + w - 1)/w)];

        // Concatenates wEncode and X into z (z = wEncode || X)
        // copy wEncode into z from z[0] to z[wEncode.length]
        System.arraycopy(wEncode, 0, z, 0, wEncode.length);
        // copy X into z from z[wEncode.length] till all X copied into z
        System.arraycopy(X,0,z,wEncode.length, X.length);

        // 2. (nothing to do: len(x) mod 8 = 0 in this byte-oriented implementation) we already made
        // sure it was a multiple of 8 on line 23.
        // 3. while (len(z)/8) mod w != 0: z= z || 00000000) Pad with zeros until desired length
        for (int i = wEncode.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }

        // 4. return z
        return z;
    }








    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/


    /**
     * For debugging purposes. Accepts and int and coverts it to a BigInteger then uses
     * method available to BigInt to covert it to a byte[].
     * @param i an integer.
     * @return byte[] of BigInteger representation of i
     */
    private static byte[] bigIntToByteArray( final int i ) {
        BigInteger bigInt = BigInteger.valueOf(i);
        return bigInt.toByteArray();
    }

    /**
     * code to reverse bits in a byte come from.
     * Author: Tom and Khalil M
     * Date: 30/7/2017
     * Location: https://stackoverflow.com/questions/3165776/reverse-bits-in-number
     * @param x byte
     * @return the byte in reversed order.
     */
    private static byte reverseBitsByte(byte x) {
        byte b = 0;
        for (int i = 0; i < 8; ++i) {
            b<<=1;
            b|=( x &1);
            x>>=1;
        }
        return b;
    }

    /**
     * Concatenates two byte[] in the order they are given
     * @param b1 byte[] to be appended onto
     * @param b2 byte[] to be appended
     * @return the concatenation of b1 and b2 (b1 || b2)
     */
    private static byte[] concat(byte[] b1, byte[] b2) {
        byte[] z = new byte[b1.length + b2.length];
        System.arraycopy(b1,0,z,0,b1.length);
        System.arraycopy(b2,0,z,b1.length,b2.length);
        return z;
    }



    /************************************************************
     *                          Driver                          *
     ************************************************************/

    public static void main(String[] args) {
        // 2^8 = 255, 2^16 = 65536, 2^3 = 16777216

        byte[] b = rightEncode(BigInteger.valueOf(16777216));
        byte[] c = leftEncode(BigInteger.valueOf(2));
        byte d = (byte) 255;
        byte[] e = {0,0};


        System.out.println("reversed value of byte c: " + reverseBitsByte(d));
        System.out.println("byte array of rightEncode: " + Arrays.toString(b));
        System.out.println("byte array of leftEncode: " + Arrays.toString(c));
        System.out.println("Concatenation of b and c (b || c): " + Arrays.toString(concat(b,c)));
        System.out.println("encodeString(e): " + Arrays.toString(encodeString(e)));
        System.out.println("Representation of BigInteger as a byte array: " + Arrays.toString(bigIntToByteArray(16777215)));

    }

}
