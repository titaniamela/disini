package rsa;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author Shania
 */
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
public class RSASignature {
    
    public static void main(String[] args) throws Exception {
        
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        BigInteger e = rsaPublicKey.getPublicExponent();
        

        
        // Print generated prime numbers and keys
        System.out.println("Generated Prime Numbers:");
        System.out.println("p: " + ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus().toString());
        System.out.println("q: " + ((java.security.interfaces.RSAPrivateKey) privateKey).getPrivateExponent().toString());
        System.out.println("e: " + e.toString());
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        
        // Create message to be signed
        String message = "Hello, this is a message to be signed.";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        // Create hash of message using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(messageBytes);
        
        // Create digital signature of hash using private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        byte[] digitalSignature = signature.sign();
        
        // Print digital signature
        System.out.println("Digital Signature: " + Base64.getEncoder().encodeToString(digitalSignature));
    }
}
