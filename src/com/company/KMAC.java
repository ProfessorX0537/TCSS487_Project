package com.company;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;

public class KMAC {

    /**
     * The round constants defined by specification of which there are 24
     */
    private static final long[] keccakfRndc = {
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
    private static final int[] keccakfRotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * The position for each word with respect to lane shifts in pi function
     */
    private static final int[] keccakfPilane = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /************************************************************
     *                    Keccak Machinery                      *
     ************************************************************/


    /**
     * The Keccack-p permutation, ref section 3.3 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the Keccak-p permutation has been applied
     */
    private static long[] keccakp(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i); // sec 3.3 FIPS 202
        }

        System.out.println("stateout in keccakp: " + Arrays.toString(stateOut));

        //TODO: stateout has different values between the two

        System.out.println("stateout in bytearray: \n" + Arrays.toString(stateToByteArray(stateOut, rounds)));


        return stateOut;
    }

    /**
     * The theta function, ref section 3.2.1 NIST FIPS 202. xors each state bit
     * with the parities of two columns in the array.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the theta function has been applied (array of longs)
     */
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i+4) % 5] ^ rotLane64(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * The rho and phi function, ref section 3.2.2-3 NIST FIPS 202. Shifts and rearranges words.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the rho and phi function
     */
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0]; // first value needs to be copied
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = keccakfPilane[i];
            temp = stateIn[ind];
            stateOut[ind] = rotLane64(t, keccakfRotc[i]);
            t = temp;
        }
        return stateOut;
    }

    /**
     * The chi function, ref section 3.2.4 NIST FIPS 202. xors each word with
     * a function of two other words in their row.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the chi function
     */
    private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i+1) % 5 + 5*j] & stateIn[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the round constant to the word at stateIn[0].
     * ref. section 3.2.5 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the round constant has been xored with the first lane (st[0])
     */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= keccakfRndc[round];
        return stateIn;
    }

    /**
     * The sponge function, produces an output of length bitLen based on the
     * keccakp permutation over in.
     * @param in the input byte array
     * @param bitLen the length of the desired output
     * @param cap the capacity see section 4 FIPS 202.
     * @return a byte array of bitLen bits produced by the keccakp permutations over the input
     */
    private static byte[] sponge(byte[] in, int bitLen, int cap) {
        System.out.println("data in to sponge: " + bytesToHexString(in));
        int rate = 1600 - cap;
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in); // one bit of padding already appended
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = keccakp(xorStates(stcml, st), 1600, 24); // Keccak[c] restricted to bitLen 1600
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate / 64);
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            stcml = keccakp(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);

        System.out.println("data out of sponge before cut short: " + bytesToHexString( padded));
        System.out.println("data out of sponge: " + bytesToHexString( stateToByteArray(out, bitLen)));
        return stateToByteArray(out, bitLen);
    }

    /**
     * Applies the 10*1 padding scheme, ref sec 5.1 FIPS 202, to a byte array. Assumes
     * padding required is byte wise (number of bits needed is multiple of 8).
     * @param in the bytes array to pad
     * @param rate the result will be a positive multiple of rate (in terms of bit length)
     * @return the padded byte array
     */
    private static byte[] padTenOne(int rate, byte[] in) {
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        byte[] padded = new byte[in.length + bytesToPad];
        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) padded[i] = in[i];
            else if (i==in.length + bytesToPad - 1) padded[i] = (byte) 0x80; // does not append any domain prefixs
            else padded[i] = 0;
        }

        return padded;
    }

    /************************************************************
     *                        KMACXOF256                        *
     ************************************************************/

    /**
     * Produces a variable length message digest based on the keccak-f perumation
     * over the user input. Ref. NIST FIPS 202 sec. 6.2
     * @param in the bytes to compute the digest of
     * @param bitLen the desired length of the output
     * @return the message digest extracted from the keccakp based sponge
     */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        int bytesToPad = 136 - in.length % (136); // rate is 136 bytes
        uin[in.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f; // pad with suffix defined in FIPS 202 sec. 6.2
        return sponge(uin, bitLen, 512);
    }

    /**
     * cSHAKE func ref sec 3.3 NIST SP 800-185
     * @param in the byte array to hash
     * @param bitLen the bit length of the desired output
     * @param funcName the name of the function to use
     * @param custStr the customization string
     * @return the message digest based on Keccak[512]
     */
    public static byte[] cSHAKE256(byte[] in, int bitLen, byte[] funcName, byte[] custStr) {
        if (funcName.length == 0 && custStr.length == 0) return SHAKE256(in, bitLen);

        byte[] fin = concat(encodeString(funcName), encodeString(custStr));
        fin = concat(bytePad(fin, 136), in);
        fin = concat(fin, new byte[] {0x04});

        System.out.println("Bytes before sponge: \n" + bytesToHexString(fin));

        return sponge(fin, bitLen, 512);
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

        System.out.println("bytepad data right before return:\n " + bytesToHexString(z));

        // 4. return z
        return z;
    }




    /**
     * Will perform some bit rotation on a given lane
     * @param x lane
     * @param y amount of rotation
     * @return the lane rotated
     */
    private static long rotLane64(long x, int y) {
        return (x << (y%64)) | (x >>> (64 - (y%64)));
    }


    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }

    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    /**
     * Converts an extended state array to an array of bytes of bit length bitLen (equivalent to Trunc_r).
     * @param state the state to convert to a byte array
     * @param bitLen the bit length of the desired output
     * @return a byte array of length bitLen/8 corresponding to bytes of the state: state[0:bitLen/8]
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length*64 < bitLen) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLen/8];
        int wrdInd = 0;
        while (wrdInd*64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
            }
        }

        return out;
    }

    /**
     * Converts a byte array to series of state arrays. Assumes input array is
     * evenly divisible by the rate (1600-cap)
     * @param in the input bytes
     * @param cap the capacity see section 4 FIPS 202.
     * @return a two dimensional array corresponding to an array of in.length/(1600-cap) state arrays
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600-cap)/64; j++) {
                long word = bytesToWord(offset, in);
                state[j] = word;
                offset += 8;
            }
            // remaining (capacity/64) words will be 0, ref alg 8. step 6 FIPS 202
            states[i] = state;
        }
        return states;
    }

    /**
     * Converts the bytes from in[l,r] into a 64 bit word (long)
     * @param offset the position in the array to read the eight bytes from
     * @param in the byte array to read from
     * @return a long that is the result of concatenating the eight bytes beginning at offset
     */
    private static long bytesToWord(int offset, byte[] in) {
        if (in.length < offset+8) throw new IllegalArgumentException("Byte range unreachable, index out of range.");
        // does endianness matter here?
        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
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



//        Scanner userIn = new Scanner(System.in);
//        do {
//            selectService(userIn);
//        } while (repeat(userIn));
//        userIn.close();

        String data = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F " +
                "20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F " +
                "30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F " +
                "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F " +
                "50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F " +
                "60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F " +
                "70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F " +
                "80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F " +
                "90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F " +
                "A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF " +
                "B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF " +
                "C0 C1 C2 C3 C4 C5 C6 C7";
        String n = "";
        String s = "Email Signature";

        //cSHAKE256(data.getBytes(),512, n.getBytes(), s.getBytes());
        System.out.println("Encoded n: \n" + bytesToHexString(encodeString(n.getBytes())));
        System.out.println("Encoded s: \n" + bytesToHexString(encodeString(s.getBytes())));
//        byte[] bPad= bytePad(concat(encodeString(n.getBytes()), encodeString(s.getBytes())), 136);
//        System.out.println("bytepad data:\n" + bytesToHexString(bPad));

        cSHAKE256(hexStringToBytes(data), 512, n.getBytes(), s.getBytes());

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
