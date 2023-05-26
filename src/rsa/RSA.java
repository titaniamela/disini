package rsa;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author Shania
 */

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.swing.JFileChooser;

public class RSA {
    private static final int CERTAINTY = 10;
    private static final int KEY_LENGTH = 64;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        // generate primes
        BigInteger p = generatePrime();
        BigInteger q = generatePrime();
        Halaman1.bilP.setText(p.toString());
        Halaman1.bilQ.setText(q.toString());
        //System.out.println("p: " + p);
        //System.out.println("q: " + q);

        // calculate n and phi(n)
        BigInteger n = p.multiply(q);
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // generate public and private keys
        BigInteger e = generatePublicKey(phiN);
        BigInteger d = generatePrivateKey(e, phiN);
        Halaman1.bilE.setText(e.toString());
        //System.out.println("e: " + e);
        Halaman1.KPublik.setText("(" + e + "," + n + ")");
        Halaman1.KPrivat.setText("(" + d + "," + n + ")");
        //System.out.println("Public key (e,n): (" + e + "," + n + ")");
        //System.out.println("Private key (d,n): (" + d + "," + n + ")");

        // hash message
        //Halaman2.txtDisplay.setText(Halaman2.txtDisplay.getText());
        //Halaman3.txtContent.setText(Halaman2.txtDisplay.getText());
        /*String message = Halaman3.txtContent.getText();
        byte[] hash = sha256(message.getBytes(StandardCharsets.UTF_8));
        Halaman3.txtDigest.setText(bytesToHex(hash));*/
        //System.out.println("Hash: " + bytesToHex(hash));
        String  filePath = Hal2.txtPATH.getText();
        byte[] hash = calculateFileHash(filePath);
       
        
        // encrypt hash with private key
        BigInteger encryptedHash = new BigInteger(hash).modPow(d, n);
        //Halaman4.txtFinal.setText(encryptedHash.toString());
        
        // write digital signature and public key to file
        /*try (FileWriter writer = new FileWriter("Digital_Signature.txt")) {    
            //writer.write("Original Message: " + message + "\n \n");
            writer.write("Digital Signature: " + encryptedHash.toString() + "\n \n");
            //writer.write("Public Key (e,n): " + "(" + e + "," + n + ")");
            //String publicKeyString = Halaman1.KPublik.getText().replaceAll("\\s", ""); // hapus whitespace
            //writer.write("Public Key (e,n): " + publicKeyString);
            //writer.write("Public Key (e,n): " + Halaman1.KPublik.getText().replaceAll("\\(", "").replaceAll("\\)", ""));
        } catch (IOException ex) {
            ex.printStackTrace();
        }*/
        String signatureFilePath = getSignatureFilePath(filePath);
        try (FileWriter writer = new FileWriter(signatureFilePath)) {
            writer.write("Digital Signature: " + encryptedHash.toString() + "\n");
            //writer.write("Public Key (e,n): " + Halaman1.KPublik.getText().replaceAll("\\(", "").replaceAll("\\)", ""));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
       
        
    }

    private static BigInteger generatePrime() {
        Random random = new Random();
        BigInteger prime = new BigInteger(KEY_LENGTH,  random);

        while (!prime.isProbablePrime(CERTAINTY)) {
            prime = new BigInteger(KEY_LENGTH, CERTAINTY, random);
        }

        return prime;
    }

    private static BigInteger generatePublicKey(BigInteger phiN) {
        Random random = new Random();
        BigInteger e = BigInteger.probablePrime(phiN.bitLength() - 1, random);

        while (!phiN.gcd(e).equals(BigInteger.ONE)) {
            e = BigInteger.probablePrime(phiN.bitLength() - 1, random);
        }

        return e;
    }

    private static BigInteger generatePrivateKey(BigInteger e, BigInteger phiN) {
        return e.modInverse(phiN);
    }

    /*private static byte[] sha256(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }*/
    private static byte[] calculateFileHash(String filePath) throws NoSuchAlgorithmException, IOException {
        Path path = Paths.get(filePath);
        byte[] fileData = Files.readAllBytes(path);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(fileData);
    }

   /* private static String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }*/
    private static String getSignatureFilePath(String filePath) {
        int dotIndex = filePath.lastIndexOf('.');
        String signatureFilePath = filePath.substring(0, dotIndex) + ".signature.txt";
        return signatureFilePath;
    }
}
