package com.company;

import java.lang.reflect.Array;
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
        return (x << (y%64)) | (x >>> (64 - (y%64)));
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

    public void sha3Update(byte[]  data, int len) {
        byte[] z = new byte[len];
        System.arraycopy(data, 0,z, 0,data.length);
        System.out.println("length of data: " + data.length + "length " + len);;
        System.out.println("sha3Update data in: \n" + bytesToHexString(data));
        System.out.println("sha3Update emptyState Before: \n" + bytesToHexString(emptyState));
        int j = this.pt;
        //System.out.println("About to Absorb data:\n" + bytesToHexString(this.emptyState));
        //System.out.println("Data to be absorbed:\n" + bytesToHexString(data));
        for (int i = 0; i < len; i++) {
            //TODO: out of bounds?
            this.emptyState[j++] ^= z[i];
            if (j >= this.rsiz) {
                sha3Keccakf(emptyState);
                j = 0;
            }
        }
        System.out.println("sha3Update emptyState after: \n" + bytesToHexString(emptyState));
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

    private static byte[] SHAKE256(byte[] in, int bitLength) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        int bytesToPad = 136 - in.length % (136);
        uin[in.length] =  bytesToPad == 1 ? (byte) 0x9f :0x1f;


        byte[] s = {};
        return s;
    }


    /**
     * Function cSHAKE256
     *
     * @param in is the main input bit string of any length
     * @param bitLength is an integer representing the requested output length in bits
     * @param funcName is a function-name bit string
     * @param customString is a customization bit string
     * @return either SHAKE or KECCAK
     */
    private static byte[] cSHAKE256(byte[] in, int bitLength, byte[] funcName, byte[] customString) {
        Main sha = new Main();
        if (funcName.length == 0 && customString.length == 0) { // use cSHAKE
            return SHAKE256(in, bitLength);
        }

        byte[] bPad = concat(bytePad(concat(encodeString(funcName),encodeString(customString)), 136),in );
        bPad = concat(bPad, new byte[]{0x04});
        byte[] s = {};
        return s;


//        Main sha = new Main();
//        boolean cSHAKE = false;
//        byte[] result = new byte[bitLength >>> 3];
//
//        sha.sha3Update(in, in.length);
//        sha.xof(cSHAKE);
//        sha.shakeOut(result, bitLength >>> 3);
//        return result;
    }

    /**
     * The Keccak MAC with extensible output
     *
     * @param key is a key bit string of any length, including zero
     * @param in is the main input bit string
     * @param bitLength is an integer representing the requested output length in bits
     * @param customString is an optional customization bit string
     * @return cSHAKE256
     */
    public static byte[] KMACXOF256(byte[] key, byte[] in, int bitLength, byte[] customString) {

        byte[] newX = concat(concat(bytePad(encodeString(key),136), in), rightEncode(BigInteger.ZERO));
        return cSHAKE256(newX, bitLength, "KMAC".getBytes(), customString);
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
            //xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i+1)] = xBytes[i];
        }
        // 4. let xBytes.length + 1 = enc8(n). That is appended the reversed byte representation
        // of n to the end of xBytes.
        //output[output.length-1] = reverseBitsByte((byte)n);
        output[0] =(byte)n;
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
            //xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i)] = xBytes[i];
        }
        // 4. let xBytes.length + 1 = enc8(n). That is appended the reversed byte representation
        // of n to the end of xBytes.
//        output[0] = reverseBitsByte((byte)n);
        output[0] =(byte)n;
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
            System.out.println(S.length);
            return concat(leftEncode(new BigInteger(String.valueOf(S.length << 3))), S);
        }
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @author Paulo Barreto
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    private static byte[] bytePad(byte[] X, int w) {
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
        int newline = 0;
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if(space == 1) {
                hex.append(" ");
                space = 0;
            }
            if(newline == 16) {
                hex.append("\n");
                newline = 0;
            }

            hex.append(String.format("%02X", b[i]));
            space++;
            newline++;
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
            selectServicePrompt(userIn);
        } while (repeat(userIn));
        userIn.close();

        String data = "00 01 02 03";
        String n = "";
        String s = "Email Signature";

        //cSHAKE256(data.getBytes(),512, n.getBytes(), s.getBytes());
        System.out.println(bytesToHexString(encodeString(n.getBytes())));
        System.out.println(bytesToHexString(encodeString(s.getBytes())));
        byte[] bPad= bytePad(concat(encodeString(n.getBytes()), encodeString(s.getBytes())), 136);
        System.out.println("bytepad data:\n" + bytesToHexString(bPad));

        cSHAKE256(hexStringToBytes(data), 512, n.getBytes(), s.getBytes());

    }

    /*************************************************************
     *                          Prompts                          *
     *************************************************************/

    private static void selectServicePrompt(final Scanner userIn) {
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
        } else {
            System.out.println("test 4");
        }
    }

    private static String fileOrInputPrompt(Scanner userIn) {
        String menuPrompt = """
                What format would you like your input:
                    1) File
                    2) User inputted string through command line
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 2);
        if (response == 1) {
            return "file";
        } else {
            return "user input";
        }
    }

    private static String decryptPreviousEncryptOrGivenCryptogram(Scanner userIn) {
        String menuPrompt = """
                What format would you like your input:
                    1) Most recently encrypted (requires use of encryption service first).
                    2) User inputted cryptogram
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 2);
        if (response == 1) {
            return "prev encrypt";
        } else {
            return "user input";
        }
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

    /**************************************************************
     *                          Services                          *
     **************************************************************/

    /**
     * Driver method for the plain hash service.
     * Prints out a plain cryptographic hash for the given input using KMACXOF256.
     * The user can choose between a file or command line for input.
     * @param input the input method, "file" for file input and "user input" for command line input.
     */
    private static void plainHashService(final String input) {
        //input will be "file" or "user input"
        byte[] byteArray;
        String theString = null;
        Scanner userIn = new Scanner(System.in);

        if (input.equals("file")) { //input from file
            File inputFile = getUserInputFile(userIn);
            theString = fileToString(inputFile);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("Please enter a phrase to be hashed: ");
            theString = userIn.nextLine();
        }

        assert theString != null;
        byteArray = theString.getBytes();
        byteArray = KMACXOF256("".getBytes(), byteArray, 512, "D".getBytes());
        System.out.println(bytesToHexString(byteArray));
    }

    /**
     * Driver method for the authentication tag service.
     * Prints out an authentication tag (MAC) for the given input under a given passphrase using KMACXOF256.
     * The user can choose between a file or command line for input.
     * @param input the input method, "file" for file input and "user input" for command line input.
     */
    private static void authTagService(final String input) {
        //input will be "file" or "user input"
        byte[] byteArray;
        String thePhrase = null;
        String thePassphrase = null;
        Scanner userIn = new Scanner(System.in);

        if (input.equals("file")) { //input from file
            File inputFile = getUserInputFile(userIn);
            thePhrase = fileToString(inputFile);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("Please enter a phrase to be hashed: ");
            thePhrase = userIn.nextLine();
        }

        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        assert thePhrase != null;
        byteArray = thePhrase.getBytes();
        byteArray = KMACXOF256(thePassphrase.getBytes(), byteArray, 512, "T".getBytes());
        System.out.println(bytesToHexString(byteArray));
    }

    /**
     * Driver method for the encryption service.
     * Prints out an encrypted version for the given input file under a given passphrase.
     */
    private static void encryptService() {
        Scanner userIn = new Scanner(System.in);
        File theFile = getUserInputFile(userIn);
        String theFileContent = fileToString(theFile);
        String thePassphrase;
        byte[] byteArray = theFileContent.getBytes();
        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        prevEncrypt = encrypt(byteArray, thePassphrase);
        System.out.println(bytesToHexString(prevEncrypt));
    }

    /**
     * Driver method for the decryption service.
     * Prints out a decrypted version for the given symmetric cryptogram under a given passphrase.
     */
    private static void decryptService(String input) {
        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        byte[] decryptedByteArray;
        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        if (input.equals("prev encrypt")) { //input from file
            decryptedByteArray = decrypt(prevEncrypt, thePassphrase);
            System.out.println(bytesToHexString(decryptedByteArray));
        } else if (input.equals("user input")) { //input from command line


        }

    }

//    private static byte[] hashByteArray(byte[] m) { return KMACXOF256("".getBytes(), m, 512, "D".getBytes()); }
//
//    private static byte[] authenticationTag(byte[] m, String pw) { return KMACXOF256(pw.getBytes(), m, 512, "T".getBytes()); }

    /**
     * Helper method that contains the logical work of the encryption service.
     * @param m the byte array to be encrypted.
     * @param pw the passphrase given by the user.
     * @return an encrypted version of the given byte array.
     */
    private static byte[] encrypt(byte[] m, String pw) {
        byte[] rand = new byte[64];
        z.nextBytes(rand);
        byte[] keka = KMACXOF256(concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);
        
        byte[] c = KMACXOF256(ke, "".getBytes(), (m.length * 8), "SKE".getBytes());
        c =  xorBytes(c, m);
        byte[] t = KMACXOF256(ka, m, 512, "SKA".getBytes());

        System.out.println("tag in encrypt: \n" + bytesToHexString(t));

        return concat(concat(rand, c), t);
    }

    /**
     * Helper method that contains the logical work of the decryption service.
     * @param cryptogram the symmetric cryptogram to be decrypted.
     * @param pw the passphrase given by the user.
     * @return a decrypted version of the given cryptogram.
     */
    private static byte[] decrypt(byte[] cryptogram, String pw) {
        byte[] rand = new byte[64];
        System.arraycopy(cryptogram, 0, rand, 0, 64);

        byte[] c = new byte[cryptogram.length - 128];
        System.arraycopy(cryptogram, 64, c, 0, cryptogram.length - 128);

        System.out.println("This should match t from encrypt: \n" + bytesToHexString(c));

        byte[] keka = KMACXOF256(concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = KMACXOF256(ke, "".getBytes(), (c.length * 8), "SKE".getBytes());
        m = xorBytes(m, c);

        byte[] tPrime = KMACXOF256(ka, m, 512, "SKA".getBytes());
        return concat(concat(c, tPrime), m);
    }

    /**************************************************************
     *                        User Input                          *
     **************************************************************/

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
     * Asks the user for a file path.
     * If correctly verified, the method will create a File object from that path.
     * @param userIn the scanner used when asking the user for the file path.
     * @return the File object created from the verified path.
     */
    public static File getUserInputFile(final Scanner userIn) {
        File theFile;
        boolean pathVerify = false;
        String filePrompt = "Please enter the full path of the file:";
        do {
            System.out.println(filePrompt);
            theFile = new File(userIn.nextLine());
            if (theFile.exists()) {
                pathVerify = true;
            } else {
                System.out.println("ERROR: File doesn't exist.");
            }
        } while (!pathVerify);

        return theFile;
    }

    /*************************************************************
     *                          Helpers                          *
     *************************************************************/

    /**
     * Converts the content of a file to String format.
     * @param theFile the File object to be converted.
     * @return the converted String object.
     */
    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }

}

