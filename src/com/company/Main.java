package com.company;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Main class of NIST compliant implementation of KMACX0F256
 * Takes heavy inspiration from majossarinen's C implementation which can be found here
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
    private byte[] emptyState = new byte[200];

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

    /**
     * Keccak-f sponge construction and permutations
     * @param v The complete permutation state array
     */
    private void sha3Keccakf(byte[] v) {
        long[] bc = new long[5];
        long[] state = new long[25];
        long t;

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            state[i] = (((long)v[j + 0] & 0xFFL))    | (((long)v[j + 1] & 0xFFL) <<  8) |
                    (((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
                    (((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
                    (((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
        }

        // actual iteration
        for (int r = 0; r < keccakfRnds; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ rotLane64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5)
                    state[j + i] ^= t;
            }

            // Rho Pi
            t = state[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakfPilane[i];
                bc[0] = state[j];
                state[j] = rotLane64(t, keccakfRotc[i]);
                t = bc[0];
            }

            //  Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++)
                    bc[i] = state[j + i];
                for (int i = 0; i < 5; i++)
                    state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            //  Iota
            state[0] ^= keccakfRndc[r];
        }

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j+=8) {
            t = state[i];
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
     *                        KMACXOF256                        *
     ************************************************************/

    /**
     * Initializes the state array for sha3Keccakf
     * @param mdlen
     */
    private void sha3Init(int mdlen) {
        for (int i = 0; i < 200; i++) {
            this.emptyState[0] = (byte) 0;
        }
        this.mdlen = mdlen;
        this.rsiz = 200 - 2 * mdlen;
        this.pt = 0;
    }

    public void sha3Update(byte[] data, int len) {
        int j = this.pt;
        for (int i = 0; i < len; i++) {
            this.emptyState[j++] ^= data[i];
            if (j >= this.rsiz) {
                sha3Keccakf(emptyState);
                j = 0;
            }
        }
        this.pt = j;
    }

    /**
     * Switch form absorbing to extensible squeezing.
     */
    public void xof(boolean iscSHAKE) {

        if (iscSHAKE) {
            this.emptyState[this.pt] ^= 0x04; // cSHAKE is 00
        } else {
            this.emptyState[this.pt] ^= 0x1F; // SHAKE is 1111
        }
        this.emptyState[this.rsiz-1] ^= (byte) 0x80;
        sha3Keccakf(this.emptyState);
        this.pt = 0;
    }

    public void shakeOut(byte[] out, int len) {
        int j = this.pt;
        for (int i = 0; i < len; i++) {
            if (j >= this.rsiz) {
                sha3Keccakf(this.emptyState);
                j = 0;
            }
            out[i] = this.emptyState[j++];
        }
        this.pt = j;
    }

    /**
     *
     * @param N is a function-name bit string
     * @param S is a customization bit string
     */
    private void cSHAKE256Helper(byte[] N, byte[] S) {
        sha3Init(SHAKE256);
        byte[] bPad= bytepad(concat(encodeString(N), encodeString(S)), 136);
        sha3Update(bPad, bPad.length);
    }

    /**
     * Function cSHAKE256
     *
     * @param X is the main input bit string of any length
     * @param L is an integer representing the requested output length in bits
     * @param N is a function-name bit string
     * @param S is a customization bit string
     * @return either SHAKE or KECCAK
     */
    private static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        Main sha = new Main();
        boolean cSHAKE = false;
        byte[] result = new byte[L >>> 3];
        if (N.length != 0 && S.length != 0) { // use cSHAKE
            sha.cSHAKE256Helper(N, S);
            cSHAKE = true;
        }
        sha.sha3Update(X, X.length);
        sha.xof(cSHAKE);
        sha.shakeOut(result, L >>> 3);
        return result;
    }

    /**
     * Function KMACXOF256
     *
     * @param K is a key bit string of any length, including zero
     * @param X is the main input bit string
     * @param L is an integer representing the requested output length in bits
     * @param S is an optional customization bit string
     * @return cSHAKE256
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {

        byte[] newX = concat(concat(bytepad(encodeString(K),136), X), rightEncode(BigInteger.ZERO));
        return cSHAKE256(newX, L, "KMAC".getBytes(), S);
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

    /**
     * Converts byte array to Hex representation String
     * https://mkyong.com/java/java-how-to-convert-bytes-to-hex/
     * @param b bytes to be converted
     * @return string representing hex equivalent
     */
    private static String bytesToHexString(byte[] b)  {
        int space = 0;
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if(space == 1) {
                hex.append(" ");
                space = 0;
            }
            hex.append(String.format("%02X", b[i]));
            space++;
        }
        return hex.toString();
    }

    /**
     * Takes a String representation of Hex values and coverts it to a byte array.
     * https://www.tutorialspoint.com/convert-hex-string-to-byte-array-in-java#:~:text=To%20convert%20hex%20string%20to,length%20of%20the%20byte%20array.
     * @param s String of hex values
     * @return byte array
     */
    private static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length()/2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index,index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }



    /************************************************************
     *                          Driver                          *
     ************************************************************/

    public static void main(String[] args) {
        // 2^8 = 255, 2^16 = 65536, 2^3 = 16777216

//        byte[] b = rightEncode(BigInteger.valueOf(16777216));
//        byte[] c = leftEncode(BigInteger.valueOf(2));
//        byte d = (byte) 255;
//        byte[] e = {0,0};
//
//
//        System.out.println("reversed value of byte c: " + reverseBitsByte(d));
//        System.out.println("byte array of rightEncode: " + Arrays.toString(b));
//        System.out.println("byte array of leftEncode: " + Arrays.toString(c));
//        System.out.println("Concatenation of b and c (b || c): " + Arrays.toString(concat(b,c)));
//        System.out.println("encodeString(e): " + Arrays.toString(encodeString(e)));
//        System.out.println("Representation of BigInteger as a byte array: " + Arrays.toString(bigIntToByteArray(16777215)));
        Scanner userIn = new Scanner(System.in);
        do {
            selectService(userIn);
        } while (repeat(userIn));
        userIn.close();
    }

    private static void selectService(final Scanner userIn) {
        String menuPrompt = """
                Please enter the corresponding number of the service you would like to use:
                    1) Compute a plain cryptographic hash from a file
                    2) Compute an authentication tag (MAC)
                    3) Encrypt a given data file
                    4) Decrypt a given symmetric cryptogram
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            System.out.println("test 1");
        } else if (response == 2) {
            System.out.println("test 2");

        } else if (response == 3) {
            System.out.println("test 3");

        String s = "Email Signature";
        String data = "00 01 02 03";



        byte[] x = encodeString("".getBytes());
        System.out.println(Arrays.toString(x));
        System.out.println(bytesToHexString(x));

        } else {
            System.out.println("test 4");
        }
    }

    /**
     * Checks whether the user inputted integer is within the desired range.
     * This will keep running until the user inputs an integer that is in the desired range.
     * @param userIn is the scanner that will be used for user input.
     * @param prompt is the prompt that the user is answering from.
     * @param minMenuInput the low end of the options on the menu.
     * @param maxMenuInput the high end of the options on the menu.
     * @return the user inputted int that is within the desired range.
     */
    public static int getIntInRange(final Scanner userIn, final String prompt,
                                    final int minMenuInput, final int maxMenuInput) {
        int input = getInt(userIn, prompt);
        while (input < minMenuInput || input > maxMenuInput) {
            System.out.print("Input out of range.\nPlease enter a number that corresponds to a menu prompt.\n");
            input = getInt(userIn, prompt);
        }
        return input;
    }

    /**
     * Checks to see whether the user inputted an int or not.
     * @param userIn is the scanner that will be used for user input.
     * @param prompt is the prompt that the user is answering.
     * @return the user inputted int.
     */
    public static int getInt(final Scanner userIn, final String prompt) {
        System.out.println(prompt);
        while (!userIn.hasNextInt()) {
            userIn.next();
            System.out.println("Invalid input. Please enter an integer.");
            System.out.println(prompt);
        }
        return userIn.nextInt();
    }

    /**
     * Asks the user if they would like to repeat the program.
     * Accepted responses:
     *  Y or Yes (ignoring case)
     *  N or No (ignoring case)
     * @param userIn The scanner that will be used.
     * @return Returns true if the user would like to repeat, false if the user would like to quit.
     */
    private static boolean repeat(final Scanner userIn) {
        System.out.println("\nWould you like to use another service? (Y/N)");
        String s = userIn.next();
        System.out.println();
        return (s.equalsIgnoreCase("Y") || s.equalsIgnoreCase ("yes"));
    }

}

