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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.*;

public class RSASignatureExample {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        String message = "Hello, World!"; // pesan yang akan di-hash dan dienkripsi
        byte[] hash = hashSHA256(message); // melakukan hash pada pesan menggunakan SHA-256
        KeyPair keyPair = generateKeyPair(); // membangkitkan kunci publik dan kunci privat
        byte[] signature = encrypt(hash, keyPair.getPrivate()); // melakukan enkripsi pada nilai hash menggunakan kunci privat
        
        // mencetak nilai hash, kunci publik, kunci privat, dan tanda tangan digital
        System.out.println("Hash value: " + bytesToHex(hash));
        System.out.println("Public key: " + bytesToHex(keyPair.getPublic().getEncoded()));
        System.out.println("Private key: " + bytesToHex(keyPair.getPrivate().getEncoded()));
        System.out.println("Digital signature: " + bytesToHex(signature));
        System.out.println("p: " + keyPair.getPrivate().getEncoded()[11]);
        System.out.println("q: " + keyPair.getPrivate().getEncoded()[19]);
        System.out.println("e: " + keyPair.getPrivate().getEncoded()[39]);
        System.out.println("d: " + bytesToHex(keyPair.getPrivate().getEncoded()).substring(96));
    }
    
    // melakukan hash pada pesan menggunakan algoritma SHA-256
    public static byte[] hashSHA256(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(message.getBytes());
        return encodedHash;
    }
    
    // membangkitkan kunci publik dan kunci privat
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(512, random);
        BigInteger q = new BigInteger(512, random);
        BigInteger n = p.multiply(q);
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("65537");
        BigInteger d = e.modInverse(phiN);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
        }
        return new KeyPair(publicKey, privateKey);
    }
    
    // melakukan enkripsi pada nilai hash menggunakan kunci privat
    public static byte[] encrypt(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedData = cipher.doFinal(data);
        return encryptedData;
    }
    
    // mengubah array byte menjadi string hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}