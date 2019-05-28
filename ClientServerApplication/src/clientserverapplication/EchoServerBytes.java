/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package clientserverapplication;

/**
 *
 * @author Hunter Juhana and Jacob Worthington
 * @version 04/22/18
 *
 */
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EchoServerBytes {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        ServerSocket serverSocket = null;

        try {
            serverSocket = new ServerSocket(10007);
        } catch (IOException e) {
            System.err.println("Could not listen on port: 10007.");
            System.exit(1);
        }

        Socket clientSocket = null;
        System.out.println("Waiting for connection.....");

        try {
            clientSocket = serverSocket.accept();
        } catch (IOException e) {
            System.err.println("Accept failed.");
            System.exit(1);
        }

        System.out.println("Connection successful");
        System.out.println("Waiting for input.....");

        OutputStream out = null;
        InputStream in = null;

        out = clientSocket.getOutputStream();
        in = clientSocket.getInputStream();

        //--------------------------------------------------------------------------
        // In this part the server creates a public-private key pair for the RSA 
        // cipher and sends the public key to the client. 
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 1024;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // Generates key with RSA
        kpg.initialize(keyBitSize, secureRandom); // Initializes the 512 bits and Secure Random bytes
        KeyPair kp = kpg.generateKeyPair(); // Gets the Key Pair
        PublicKey pub = kp.getPublic(); // Sets the public key
        PrivateKey pvt = kp.getPrivate(); // Sets the private key

        // Prints statement saying the keys were generated
        System.out.println("\n" + "Generating key/value pair using " + pvt.getAlgorithm() + " algorithm");

        byte[] publicKeyBytes = new byte[128]; // Byte array with length of 128
        publicKeyBytes = pub.getEncoded(); // Converts public key to byte array
        out.write(publicKeyBytes); // Writes to the client

        // Prints the public key bytes for verification
        System.out.print("Public key bytes: ");
        for (int k = 0; k < publicKeyBytes.length; k++) {
            System.out.print(publicKeyBytes[k] + " ");
        }
        System.out.println("");

        System.out.println(pub); // Prints the public key for verification

        // Recieved the secret key in bytes. Have not decrypted the message yet.
        byte[] recievedSecretKey = new byte[128]; // byte array length of 64 
        in.read(recievedSecretKey); // reads from client the secret key

        //Prints the encrypted secret key sent across the network for verification
        System.out.print("\nSecret key encrypted: ");
        for (int k = 0; k < recievedSecretKey.length; k++) {
            System.out.print(recievedSecretKey[k] + " ");
        }
        System.out.println("");

        // The server, upon receiving the message, decrypts the message 
        // (using its private key) to recover the AES key, and sets this to be the 
        // key for an AES cipher.
        Cipher cipher = Cipher.getInstance("RSA"); // Gets a cipher with RSA
        cipher.init(Cipher.DECRYPT_MODE, pvt); // decrypts with the private key
        byte[] sessionKey = cipher.doFinal(recievedSecretKey); // decrypts the recieved secret key and stores in byte array

        // Prints secret key for verification, should match the client secret key before encryption
        System.out.print("\nSecret key: ");
        for (int k = 0; k < sessionKey.length; k++) {
            System.out.print(sessionKey[k] + " ");
        }
        System.out.println("");

        SecretKey secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        System.out.println(secretKey);

        //--------------------------------------------------------------------------
        // Part 2
        // Assuming that the session key for AES is established between the two parties, 
        // in this part of the project, the client and server exchanges messages from the users on each side. 
        PrintWriter printOut = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader readIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        System.out.println("\nBegin Server transmission. Type 'bye' to quit: ");
        String inputLine;
        String encryptedClientMsg = "";
        Scanner scan = new Scanner(System.in);
        String str = "";
        
        // Loop that ends if server types bye
        while (!str.equalsIgnoreCase("bye") || !encryptedClientMsg.equalsIgnoreCase("bye")) {

            encryptedClientMsg = readIn.readLine(); // Reads message from client

            // If the message comes in null, it breaks
            // This means client typed bye
            if (encryptedClientMsg == null) {
                break;
            }

            // The server receives the message, 
            // decrypts it using AES, and displays it on its window.
            Cipher aesCipher = Cipher.getInstance("AES"); // AES Cipher
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey); // Decrypt mode with secret key
            byte[] decryptedValue = DatatypeConverter.parseBase64Binary(encryptedClientMsg); // Decrytped bytes from the string
            byte[] bytePlaintext = aesCipher.doFinal(decryptedValue); // Decrypts the message
            String plaintext = new String(bytePlaintext); //  Converts back to string

            System.out.println("\nEncrypted Message from Client: " + encryptedClientMsg); // Prints encrypted message from client
            System.out.println("Decrypted Message from Client: " + plaintext); // Prints decrypted message from client  

            // Then, the user on the server side enters a message. 
            // The server program encrypts the message using AES and sends it to the client.
            System.out.print("\nType message to Client: ");
            str = scan.nextLine(); // Takes input from Server User
            
            //------------------------------------------------------------------
            // Part 3

            Signature privateSignature = Signature.getInstance("SHA1withRSA"); // Get Signature 
            privateSignature.initSign(pvt); // Sign with private key
            
            privateSignature.update(str.getBytes("UTF-8")); // Update the bytes of the message to the signature
            
            byte[] signature = privateSignature.sign(); // Sign message
            
            String digitalSignature = Base64.getEncoder().encodeToString(signature); // Convert signature to String

            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey); // Encrypt mode and secret key
            byte[] byteCipherText = aesCipher.doFinal(str.getBytes("UTF-8")); // Converts to encrypted bytes
            String ciphertext = DatatypeConverter.printBase64Binary(byteCipherText); // Converts back to string
            System.out.println("Encrypted Message from Server: " + ciphertext);
            
            printOut.println(digitalSignature); // Send signature
            printOut.println(ciphertext); // Sends to client

            // The communication goes on until one party prints “bye”.
            if (str.equals("bye")) {
                break;
            }
        }

        // Closes output and input streams and sockets
        printOut.close();
        readIn.close();
        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();
    }
}
