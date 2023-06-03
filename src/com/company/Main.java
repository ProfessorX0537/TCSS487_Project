package com.company;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import static com.company.KMAC.*;
import static com.company.ECArithmetic.*;

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

    private static Point G = new Point(new BigInteger("8"), new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258"));

    private static byte[] prevEncrypt;



    /************************************************************
     *                          Driver                          *
     ************************************************************/

    public static void main(String[] args) {
        // 2^8 = 255, 2^16 = 65536, 2^3 = 16777216

        Scanner userIn = new Scanner(System.in);
        int categoryResponse = selectCategoryPrompt(userIn);

        switch (categoryResponse) {
            case 1:
                do {
                    selectKMACServicePrompt(userIn);
                } while (repeat(userIn));
                userIn.close();
            case 2:
                do {
                    selectECServicePrompt(userIn);
                } while (repeat(userIn));
                userIn.close();
        }

        String data = "00 01 02 03";
        String n = "";
        String s = "Email Signature";


    }

    /*************************************************************
     *                          Prompts                          *
     *************************************************************/

    private static int selectCategoryPrompt(final Scanner userIn) {
        String menuPrompt = """
                Please enter the corresponding number of the category of service you would like to use:
                    1) SHA-3 Derived Cryptographic Hashing
                    2) Elliptic Curve Hashing
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            return 1;
        } else {
            return 2;
        }
    }

    private static void selectKMACServicePrompt(final Scanner userIn) {
        String menuPrompt = """
                Please enter the corresponding number of the service you would like to use:
                    1) Compute a plain cryptographic hash
                    2) Compute an authentication tag (MAC)
                    3) Encrypt a given data file
                    4) Decrypt a given symmetric cryptogram
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            plainHashServiceKMAC(fileOrInputPrompt(userIn));
        } else if (response == 2) {
            authTagServiceKMAC(fileOrInputPrompt(userIn));
        } else if (response == 3) {
            encryptServiceKMAC();
        } else {
            decryptServiceKMAC(decryptPreviousEncryptOrGivenCryptogram(userIn));
        }
    }

    private static void selectECServicePrompt(final Scanner userIn) {
        String menuPrompt = """
                Please enter the corresponding number of the service you would like to use:
                    1) Generate a public key to a file using an Elliptic Curve
                    2) Encrypt a data file under a given elliptic public key file and write
                       the ciphertext to a file
                    3) Decrypt a given elliptic-encrypted file from a given password and
                       write the decrypted data to a file
                    4) Sign a given file from a given password and write the signature to
                       a file
                    5) Verify a given data file and its signature file under a given public
                       key file
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 5);
        if (response == 1) {
            System.out.println("In 1");
            keyPairEC();
        } else if (response == 2) {
            System.out.println("In 2");
            encryptEC();
        } else if (response == 3) {
            System.out.println("In 3");
            decryptEC();
        } else if (response == 4) {
            System.out.println("In 4");
            signFileEC();
        } else if (response == 5) {
            System.out.println("In 5");
            verifyFileEC();
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
     *                        KMAC Services                       *
     **************************************************************/

    /**
     * Driver method for the plain hash service.
     * Prints out a plain cryptographic hash for the given input using KMACXOF256.
     * The user can choose between a file or command line for input.
     * @param input the input method, "file" for file input and "user input" for command line input.
     */
    private static void plainHashServiceKMAC(final String input) {
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
    private static void authTagServiceKMAC(final String input) {
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
    private static void encryptServiceKMAC() {
        Scanner userIn = new Scanner(System.in);
        File theFile = getUserInputFile(userIn);
        String theFileContent = fileToString(theFile);
        String thePassphrase;
        byte[] byteArray = theFileContent.getBytes();
        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        prevEncrypt = encryptKMAC(byteArray, thePassphrase);
        System.out.println(bytesToHexString(prevEncrypt));
    }

    /**
     * Driver method for the decryption service.
     * Prints out a decrypted version for the given symmetric cryptogram under a given passphrase.
     */
    private static void decryptServiceKMAC(String input) {
        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        byte[] decryptedByteArray = new byte[0];
        System.out.println("Please enter a passphrase used to encrypt: ");
        thePassphrase = userIn.nextLine();
        if (input.equals("prev encrypt")) { //input from file
            decryptedByteArray = decryptKMAC(prevEncrypt, thePassphrase);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("\nPlease input a cryptogram in hex string format in one line (spaces okay, NO NEW LINES!!!!!): \n");
            String userString = userIn.nextLine();
            byte[] hexBytes = hexStringToBytes(userString);
            decryptedByteArray = decryptKMAC(hexBytes, thePassphrase);
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
    private static byte[] encryptKMAC(byte[] m, String pw) {
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
    private static byte[] decryptKMAC(byte[] cryptogram, String pw) {
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
     *                         EC Services                        *
     **************************************************************/

    private static void keyPairEC() {
        System.out.println("uwu in key pair :3");

        File publicKeyOutputFile = new File("PublicKeyOutputEC.txt");
        File privateKeyOutputFile = new File("PrivateKeyOutputEC.txt");

        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        System.out.println("Please enter a passphrase used to encrypt: ");
        thePassphrase = userIn.nextLine();

        //Generate the key pair from the passphrase

        //s multiple of 4?
        byte[] s = KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 512, "SK".getBytes());
        Point V = exponentiation(G, new BigInteger(s));

        try {
            FileWriter publicFw = new FileWriter(publicKeyOutputFile);
            publicFw.write((bytesToHexString(V.getPx().toByteArray())) + "\n");
            publicFw.write((bytesToHexString(V.getPy().toByteArray())) + "\n");
            publicFw.close();

            FileWriter privateFw = new FileWriter(privateKeyOutputFile);
            privateFw.write(bytesToHexString(s));
            privateFw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void encryptEC() {
        System.out.println("ooo encrypt me daddy");
        Scanner userIn = new Scanner(System.in);
        File inputFile;
        File encryptOutputFile = new File("CiphertextOutput.txt");
        String input = null;

        //get input
        String s = fileOrInputPrompt(userIn);
        if ("file".equals(s)) {
            System.out.println("Chosen File :]");
            Scanner fileInputScan = new Scanner(System.in);
            inputFile = getUserInputFile(fileInputScan);
            input = fileToString(inputFile);
        } else if ("user input".equals(s)) {
            System.out.println("Chosen user input :]");
            System.out.println("Please input a message you would like to be encrypted:");
            input = userIn.nextLine();
        }

        //encrypt input data (Stored in "input" string)
        byte[] m = hexStringToBytes(input);
        //make sure k is multiple of 4
        byte[] k = new byte[64];
        z.nextBytes(k);

        Scanner stringScanner = new Scanner(input);
        Point V = new Point(new BigInteger(hexStringToBytes(stringScanner.nextLine())), new BigInteger(hexStringToBytes(stringScanner.nextLine())));

        Point W = exponentiation(V, new BigInteger(k));
        Point Z = exponentiation(G, new BigInteger(k));

        //squeeze bits from sponge
        byte[] keka = KMACXOF256(W.getPx().toByteArray(), "".getBytes(), 1024, "PK".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] c = KMACXOF256(ke, "".getBytes(), (m.length * 8), "PKE".getBytes());
        c =  xorBytes(c, m);
        byte[] t = KMACXOF256(ka, m, 512, "PKA".getBytes());

        //write the cipertext to the output file
        try {
            FileWriter cipherTextFw = new FileWriter(encryptOutputFile);
            cipherTextFw.write(bytesToHexString(Z.getPx().toByteArray()) + "\n");
            cipherTextFw.write(bytesToHexString(Z.getPy().toByteArray()) + "\n");
            cipherTextFw.write(bytesToHexString(c) + "\n");
            cipherTextFw.write(bytesToHexString(t) + "\n");
            cipherTextFw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void decryptEC() {
        System.out.println("MM decrypt :P");
        Scanner userIn = new Scanner(System.in);
        Scanner fileIn = new Scanner(System.in);
        File inputFile;
        File outputFile = new File("DecryptedEC.txt");
        String thePassphrase;
        String inputFileContents;
        String decryptedData;

        //get file
        inputFile = getUserInputFile(fileIn);

        //get passphrase
        System.out.println("Please enter a passphrase used to encrypt: ");
        thePassphrase = userIn.nextLine();

        //get file contents
        inputFileContents = fileToString(inputFile);
        Scanner stringScanner = new Scanner(inputFileContents);
        Point Z = new Point(new BigInteger(hexStringToBytes(stringScanner.nextLine())), new BigInteger(hexStringToBytes(stringScanner.nextLine())));
        byte[] c = hexStringToBytes(stringScanner.nextLine());
        byte[] t = hexStringToBytes(stringScanner.nextLine());

        //decrypt file contents

        //Make sure it is multiple of 4?
        byte[] s = KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 512, "SK".getBytes());

        Point W = exponentiation(Z, new BigInteger(s));
        //squeeze bits from sponge
        byte[] keka = KMACXOF256(W.getPx().toByteArray(), "".getBytes(), 1024, "PK".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = KMACXOF256(ke, "".getBytes(), (c.length*  8), "PKE".getBytes());
        m = xorBytes(m, c);

        byte[] tPrime = KMACXOF256(ka, m, 512, "PKA".getBytes());

        if (Arrays.equals(t, tPrime)) {
            writeToOutputFile(outputFile, bytesToHexString(m));
        }
        else {
            throw new IllegalArgumentException("Tags didn't match");
        }

    }

    private static void signFileEC() {
        System.out.println("sign FILE!");
        Scanner userIn = new Scanner(System.in);
        File inputFile;
        File signedFile = new File("SignedInputSignature.txt");
        String inputData;

        //get input
        String fileOrInputPrompt = fileOrInputPrompt(userIn);
        if ("file".equals(fileOrInputPrompt)) {
            System.out.println("Chosen File :]");
            Scanner fileIn = new Scanner(System.in);
            inputFile = getUserInputFile(fileIn);
            inputData = fileToString(inputFile);
        } else if ("user input".equals(fileOrInputPrompt)) {
            System.out.println("Chosen user input :]");
            System.out.println("Please input a message you would like to be encrypted:");
            inputData = userIn.nextLine();
        } else {
            throw new IllegalStateException("Unexpected value: " + fileOrInputPrompt(userIn));
        }

        Scanner pwScanner = new Scanner(System.in);
        System.out.println("Please enter a passphrase used to encrypt: ");
        String thePassphrase = pwScanner.nextLine();

        //sign input
        //make sure it is a multiple of 4?
        byte[] s = KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 512, "SK".getBytes());
        // make sure it is a multiple of 4?
        byte[] k = KMACXOF256(s, inputData.getBytes(),512, "N".getBytes());
        Point U = exponentiation(G, new BigInteger(k));

        byte[] h = KMACXOF256(U.getPx().toByteArray(), inputData.getBytes() ,512, "T".getBytes());
        byte[] z = (new BigInteger(k).subtract(new BigInteger(h).multiply(new BigInteger(s)))).mod(getR()).toByteArray();

        //write signed input to file
        try {
            FileWriter signedFw = new FileWriter(signedFile);
            signedFw.write(bytesToHexString(h) + "\n");
            signedFw.write(bytesToHexString(z) + "\n");
            signedFw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void verifyFileEC() {
        System.out.println("in verify file");
        Scanner userIn = new Scanner(System.in);
        File dataFile;
        File signatureFile;
        File publicKeyFile;
        String dataFileContents;
        String signatureFileContents;


        System.out.println("DATA FILE");
        dataFile = getUserInputFile(userIn);

        System.out.println("SIGNATURE FILE");
        signatureFile = getUserInputFile(userIn);
        Scanner signedFileReader = null;
        try {
            signedFileReader = new Scanner(signatureFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        assert signedFileReader != null;
        String hexStringH = signedFileReader.nextLine();
        byte[] h = hexStringToBytes(hexStringH);
        String hexStringZ = signedFileReader.nextLine();
        byte[] z = hexStringToBytes(hexStringZ);

        System.out.println("PUBLIC KEY FILE");
        publicKeyFile = getUserInputFile(userIn);
        Scanner stringScanner = null;
        try {
            stringScanner = new Scanner(publicKeyFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        assert stringScanner != null;
        Point V = new Point(new BigInteger(hexStringToBytes(stringScanner.nextLine())), new BigInteger(hexStringToBytes(stringScanner.nextLine())));

        //verify
        Point U = add(exponentiation(G, new BigInteger(z)), exponentiation(V, new BigInteger(h)));
        if (Arrays.toString(KMACXOF256(U.getPx().toByteArray(), fileToString(dataFile).getBytes(), 512, "T".getBytes())).equals(Arrays.toString(h))) {
            //successs
            System.out.println("Verification Success");
        } else {
            System.out.println("Verification Failed");
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

    /**
     * Writes all the required information to the specified output file.
     */
    private static void writeToOutputFile(File outputFile, String contents) {
        Scanner stringScan = new Scanner(contents);
        try {
            FileWriter fw = new FileWriter(outputFile);
            while (stringScan.hasNextLine()) {
                fw.write(stringScan.nextLine());
            }
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}

