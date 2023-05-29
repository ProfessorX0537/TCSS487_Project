package com.company;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import static com.company.KMAC.*;

/**
 * Main class of NIST compliant implementation of KMACX0F256
 * Takes heavy inspiration from majossarinen's C implementation which can be found here
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * @author Xavier Hines
 * @author Cage Peterson
 * @author Thomas Brookes
 */
public class Main {

    /**
     * secure random field variable
     */
    private static SecureRandom z = new SecureRandom();

    private static byte[] prevEncrypt;



    /************************************************************
     *                          Driver                          *
     ************************************************************/

    public static void main(String[] args) {
        // 2^8 = 255, 2^16 = 65536, 2^3 = 16777216

        Scanner userIn = new Scanner(System.in);
        do {
            selectServicePrompt(userIn);
        } while (repeat(userIn));
        userIn.close();

        String data = "00 01 02 03";
        String n = "";
        String s = "Email Signature";


    }

    /*************************************************************
     *                          Prompts                          *
     *************************************************************/

    private static void selectServicePrompt(final Scanner userIn) {
        String menuPrompt = """
                Please enter the corresponding number of the service you would like to use:
                    1) Compute a plain cryptographic hash
                    2) Compute an authentication tag (MAC)
                    3) Encrypt a given data file
                    4) Decrypt a given symmetric cryptogram
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            plainHashService(fileOrInputPrompt(userIn));
        } else if (response == 2) {
            authTagService(fileOrInputPrompt(userIn));
        } else if (response == 3) {
            encryptService();
        } else {
            decryptService(decryptPreviousEncryptOrGivenCryptogram(userIn));
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
        byte[] decryptedByteArray = new byte[0];
        System.out.println("Please enter a passphrase used to encrypt: ");
        thePassphrase = userIn.nextLine();
        if (input.equals("prev encrypt")) { //input from file
            decryptedByteArray = decrypt(prevEncrypt, thePassphrase);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("\nPlease input a cryptogram in hex string format in one line (spaces okay, NO NEW LINES!!!!!): \n");
            String userString = userIn.nextLine();
            byte[] hexBytes = hexStringToBytes(userString);
            decryptedByteArray = decrypt(hexBytes, thePassphrase);
        }
        System.out.println("\nDecryption in Hex format:\n" + bytesToHexString(decryptedByteArray));
        System.out.println("\nDecryption in String format:\n" + new String (decryptedByteArray, StandardCharsets.UTF_8));
    }

    /**
     * Helper method that contains the logical work of the encryption service.
     * @param m the byte array to be encrypted.
     * @param pw the passphrase given by the user.
     * @return an encrypted version of the given byte array.
     */
    private static byte[] encrypt(byte[] m, String pw) {
        byte[] rand = new byte[64];
        z.nextBytes(rand);

        //squeeze bits from sponge
        byte[] keka = KMACXOF256(concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);
        
        byte[] c = KMACXOF256(ke, "".getBytes(), (m.length * 8), "SKE".getBytes());
        c =  xorBytes(c, m);
        byte[] t = KMACXOF256(ka, m, 512, "SKA".getBytes());

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
        //retrieve 512-bit random number contacted to beginning of cryptogram
        System.arraycopy(cryptogram, 0, rand, 0, 64);

        //retrieve the encrypted message
        byte[] in = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 64);

        //retrieve tag that was appended to cryptogram
        byte[] tag = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        //squeeze bits from sponge
        byte[] keka = KMACXOF256(concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = KMACXOF256(ke, "".getBytes(), (in.length*  8), "SKE".getBytes());
        m = xorBytes(m, in);

        byte[] tPrime = KMACXOF256(ka, m, 512, "SKA".getBytes());

        if (Arrays.equals(tag, tPrime)) {
            return m;
        }
        else {
            throw new IllegalArgumentException("Tags didn't match");
        }
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

