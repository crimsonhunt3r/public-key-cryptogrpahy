/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package clientserverapplication;

/**
 *
 * @author Hunter Juhan and Jacob Worthington
 * @version 04/22/18
 *
 */
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class EchoClientBytes {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, SignatureException {

        String serverHostname = new String("127.0.0.1");

        if (args.length > 0) {
            serverHostname = args[0];
            System.out.println("Attemping to connect to host "
                    + serverHostname + " on port 10007.");
        }

        Socket echoSocket = null;

        OutputStream out = null;
        InputStream in = null;
        PrintWriter printOut = null;
        BufferedReader readIn = null;

        try {
            echoSocket = new Socket(serverHostname, 10007);
            out = echoSocket.getOutputStream();
            in = echoSocket.getInputStream();
            printOut = new PrintWriter(echoSocket.getOutputStream(), true);
            readIn = new BufferedReader(new InputStreamReader(echoSocket.getInputStream()));
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host: " + serverHostname);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for "
                    + "the connection to: " + serverHostname);
            System.exit(1);
        }

        // The client stores the public key that it receives from the server.
        byte[] publicKeyBytes = new byte[162];
        in.read(publicKeyBytes);

        System.out.print("Public key bytes: ");
        for (int k = 0; k < publicKeyBytes.length; k++) {
            System.out.print(publicKeyBytes[k] + " ");
        }
        System.out.println("");

        // Converts publicKeyBytes back into a public key using classes found online
        PublicKey publicKey
                = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        System.out.println(publicKey); // Prints public key

        // The client generates a 128-bit key for an AES cipher 
        // (using the classes and methods of crypto class), encrypts the 
        // (bytes of the) AES key using the public key of the server 
        // (using RSA), and sends it to the server.
        KeyGenerator kg = KeyGenerator.getInstance("AES"); // Generates an AES key
        SecureRandom secureRandom = new SecureRandom(); // Secure Random bytes
        int keyBitSize = 128; // number of bits
        kg.init(keyBitSize, secureRandom); // Generates key with secure random and 128 bits
        SecretKey secretKey = kg.generateKey(); // Generates secret key
        byte[] secretKeyBytes = secretKey.getEncoded(); // Converts to byte array

        // Prints secret key that was generated
        System.out.print("\nSecret key: ");
        for (int k = 0; k < secretKeyBytes.length; k++) {
            System.out.print(secretKeyBytes[k] + " ");
        }
        System.out.println("");

        // Encrypts the secret key bytes with RSA
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Converts the secret key encryption into bytes
        byte[] encryptedSecretKey = cipher.doFinal(secretKeyBytes);

        // Prints the secret key that is encrypted in bytes
        System.out.print("\nSecret key encrypted: ");
        for (int k = 0; k < encryptedSecretKey.length; k++) {
            System.out.print(encryptedSecretKey[k] + " ");
        }
        System.out.println("");

        // Writes the encrypted secret key back to the server
        out.write(encryptedSecretKey);

        System.out.println(secretKey);

        //----------------------------------------------------------------------
        // Part 2
        // Assuming that the session key for AES is established between the two parties, 
        // in this part of the project, the client and server exchanges messages from the users on each side.
        System.out.println("\nBegin Client transmission. Type 'bye' to quit: ");
        String encryptedServerMsg = "";
        String digitalSignature = "";

        // The communication starts with client getting input from the user, 
        // encrypting it using AES, and sending it to the server.
        Scanner scan = new Scanner(System.in);
        String str = scan.nextLine(); // Takes input from user

        // Loop to continue until user inputs "bye"   
        while (!str.equalsIgnoreCase("bye")) {

            Cipher aesCipher = Cipher.getInstance("AES"); // AES Cipher
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey); // Encrypts message with secret key
            byte[] byteCipherText = aesCipher.doFinal(str.getBytes("UTF-8")); // Converts encrypted string into bytess
            String ciphertext = DatatypeConverter.printBase64Binary(byteCipherText); // Converts bytes back into a string

            System.out.println("Client(encrypted): " + ciphertext);
            printOut.println(ciphertext); // Sends encrypted message to server

            digitalSignature = readIn.readLine();
            encryptedServerMsg = readIn.readLine(); // Reads encrypted message sent from server
            // If the server sends nothing, break the transmission
            // This means server typed bye on their end
            if (encryptedServerMsg == null) {
                break;
            }

            // The client decrypts it and displays it on its window.
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey); // Sets up to decrypt message with secret key
            byte[] decryptedValue = DatatypeConverter.parseBase64Binary(encryptedServerMsg); // Converts message to bytes
            System.out.println(decryptedValue.length);
            byte[] bytePlaintext = aesCipher.doFinal(decryptedValue); // Decrypts message from server
            String plaintext = new String(bytePlaintext); // Converts decrypted message to string

            System.out.println("\nEncrypted Message from Server: " + encryptedServerMsg); // Prints encrypted message
            System.out.println("Decrypted Message from Server: " + plaintext); // Prints decrypted message

            //------------------------------------------------------------------
            // Part 3
            
            Signature publicSignature = Signature.getInstance("SHA1withRSA"); // Get signature
            publicSignature.initVerify(publicKey); // Verify with public key
            publicSignature.update(plaintext.getBytes("UTF-8")); // Update

            byte[] signatureBytes = Base64.getDecoder().decode(digitalSignature); // Convert to bytes

            System.out.print("\nSignature correct: " + publicSignature.verify(signatureBytes)); // Print verification

            // The communication goes on until one party prints “bye”. 
            System.out.print("\nType message to Server: ");
            str = scan.nextLine();

        }

        // Closes input and output stream and closes the socket
        out.close();
        in.close();
        printOut.close();
        readIn.close();
        echoSocket.close();
    }
}
