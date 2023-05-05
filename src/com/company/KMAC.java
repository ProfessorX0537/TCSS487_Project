package com.company;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * Implementation of KMACXOF256
 * Inspiration for implementation of keccak sponge taken from NWc0de and mjosaarinen
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 *
 */
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
     *                    Keccak Permutations                   *
     ************************************************************/


    /**
     * The Keccak permutation function
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * @param stateIn the input state
     * @return the state after the Keccak permutations applied
     */
    private static long[] keccak(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i); // sec 3.3 FIPS 202
        }

        //System.out.println("stateout in keccakp: " + Arrays.toString(stateOut));

        //System.out.println("stateout in bytearray: \n" + Arrays.toString(stateToByteArray(stateOut, rounds)));


        return stateOut;
    }

    /**
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state
     * @return long[] the state after the theta function has been applied
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
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
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
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
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
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
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
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * @param in the input byte array
     * @param bitLen the length of the desired output
     * @param cap the capacity see section 4 FIPS 202.
     * @return a byte array of bitLen bits produced by the keccakp permutations over the input
     */
    private static byte[] sponge(byte[] in, int bitLen, int cap) {
        //System.out.println("data in to sponge: \n" + bytesToHexString(in));
        int rate = 1600 - cap;
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in); // one bit of padding already appended
        //System.out.println("data in sponge padded: \n" + bytesToHexString( padded));
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = keccak(xorStates(stcml, st), 1600, 24); // Keccak[c] restricted to bitLen 1600
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate / 64);
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            stcml = keccak(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);


        //System.out.println("data out of sponge: \n" + bytesToHexString( stateToByteArray(out, bitLen)));
        return stateToByteArray(out, bitLen);
    }

    /**
     * Applies the 10*1 padding scheme, ref sec 5.1 FIPS 202, to a byte array. Assumes
     * padding required is byte wise (number of bits needed is multiple of 8).
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
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
     * @param bitLength the bit length of the desired output
     * @param functionName the name of the function to use
     * @param customStr the customization string
     * @return the message digest based on Keccak[512]
     */
    public static byte[] cSHAKE256(byte[] in, int bitLength, byte[] functionName, byte[] customStr) {
//        System.out.println("Encoded n: \n" + bytesToHexString(encodeString(functionName)));
//        System.out.println("Encoded s: \n" + bytesToHexString(encodeString(customStr)));
//        System.out.println("Byte[] into cSHAKE256: \n" + bytesToHexString(in));
//        System.out.println("Bitlength into cSHAKE256: " + bitLength);
//        System.out.println("functionName into cSHAKE256: \n" + bytesToHexString(functionName));
//        System.out.println("customString into cSHAKE256: \n" + bytesToHexString(customStr));
        if (functionName.length == 0 && customStr.length == 0) return SHAKE256(in, bitLength);

        byte[] fin = concat(encodeString(functionName), encodeString(customStr));
//        System.out.println("Concatenation of encoded functionName and encoded customStr:\n" + bytesToHexString(fin));
//        System.out.println("bytePad of previous bytes with 136:\n" + bytesToHexString(bytePad(fin,136)));
        fin = concat(bytePad(fin, 136), in);
//        System.out.println("Concatenation of bytePad and in:\n" + bytesToHexString(fin));
        fin = concat(fin, new byte[] {0x04});

//        System.out.println("Bytes before sponge: \n" + bytesToHexString(fin));

        return sponge(fin, bitLength, 512);
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
        //System.out.println("value of n in right encode: " + n);
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
        //System.out.println("value of n in left encode: " + n);
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
            //System.out.println(S.length);
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

//        System.out.println("bytePad returned at end of bytePad function:\n" + bytesToHexString(z));

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


    /**
     * find the max modulo 2 exponent possible in n
     * @param n
     * @return
     */
    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }

    /**
     * will xor the given long array with another given long array
     * @param s1 long array
     * @param s2 long array
     * @return the xor of s1 and s2
     */
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

    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }

    /**
     * Concatenates two byte[] in the order they are given
     * @param b1 byte[] to be appended onto
     * @param b2 byte[] to be appended
     * @return the concatenation of b1 and b2 (b1 || b2)
     */
    public static byte[] concat(byte[] b1, byte[] b2) {
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
    public static String bytesToHexString(byte[] b)  {
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
    public static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length()/2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index,index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }

}
