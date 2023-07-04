/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rsa;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

/**
 *
 * @author Shania
 */
public class iniRSA {
    private static final int CERTAINTY = 10;
    private static final int KEY_LENGTH = 64;

    public static void main(String[] args) {
        try {
            // generate primes
            BigInteger p = generatePrime();
            BigInteger q = generatePrime();
            //System.out.println("p: " + p);
            //System.out.println("q: " + q);
            Halaman1.bilP.setText(p.toString());
            Halaman1.bilQ.setText(q.toString());

            // calculate n and phi(n)
            BigInteger n = p.multiply(q);
            BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // generate public and private keys
            BigInteger e = generatePublicKey(phiN);
            BigInteger d = generatePrivateKey(e, phiN);
            //System.out.println("e: " + e);
            //System.out.println("d: " + d);
            Halaman1.bilE.setText(e.toString());
            Halaman1.KPublik.setText("(" + e + "," + n + ")");
            Halaman1.KPrivat.setText("(" + d + "," + n + ")");

            // hash message
            String filePath = Halaman2.txtPath.getText();
            byte[] hash = calculateFileHash(filePath);

            // encrypt hash with private key
            BigInteger encryptedHash = new BigInteger(1, hash).modPow(d, n);

            String signatureFilePath = getSignatureFilePath(filePath);
            try (FileWriter writer = new FileWriter(signatureFilePath)) {
                writer.write("Digital Signature: " + encryptedHash.toString() + "\n");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static BigInteger generatePrime() {
        Random random = new Random();
        BigInteger prime = new BigInteger(KEY_LENGTH, random);

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

    public static byte[] calculateFileHash(String filePath) throws NoSuchAlgorithmException, IOException {
        Path path = Paths.get(filePath);
        byte[] fileData = Files.readAllBytes(path);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(fileData);
    }

    private static String getSignatureFilePath(String filePath) {
        int dotIndex = filePath.lastIndexOf('.');
        String signatureFilePath = filePath.substring(0, dotIndex) + ".signature.txt";
        return signatureFilePath;
    }    
}
