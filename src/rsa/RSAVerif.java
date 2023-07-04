/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.swing.JOptionPane;
import static rsa.Hal3.tdata;
import static rsa.Hal3.tsign;

/**
 *
 * @author Shania
 */
public class RSAVerif {
    public static void main(String[] args) {
        String publicKey = Halaman1.KPublik.getText();
        String signaturePath = tsign.getText(); // Ganti dengan path file signature sebelumnya
        String messagePath = tdata.getText(); // Ganti dengan path file pesan yang ingin diverifikasi
        
        boolean isValid = verifySignature(publicKey, signaturePath, messagePath);
        
        if (isValid) {
            JOptionPane.showMessageDialog(null, "Digital signature valid.", "Valid", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "Digital signature tidak valid.", "Tidak Valid", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static boolean verifySignature(String publicKey, String signaturePath, String messagePath) {
        // Mendapatkan nilai eksponen (e) dan modulus (n) dari kunci publik
        String valueInParentheses = publicKey.substring(publicKey.indexOf("(") + 1, publicKey.indexOf(")"));
        String[] publickeyParts = valueInParentheses.split(",");
        BigInteger e = new BigInteger(publickeyParts[0].trim());
        BigInteger n = new BigInteger(publickeyParts[1].trim());

        // Membaca signature dari file
        String signature = readSignatureFromFile(signaturePath);

        // Membaca message dari file
        byte[] message = readMessageFromFile(messagePath);

        // Hitung nilai hash dari pesan asli
        byte[] messageHash = sha256(message);

        // Dekripsi digital signature menggunakan kunci publik
        BigInteger decryptedSignature = new BigInteger(signature).modPow(e, n);

        // Konversi nilai hash dari pesan asli ke BigInteger
        BigInteger calculatedHash = new BigInteger(1, messageHash);

        // Verifikasi digital signature
        boolean isValid = decryptedSignature.equals(calculatedHash);
        return isValid;
    }


    private static String readSignatureFromFile(String path) {
        try {
            String fileContent = new String(Files.readAllBytes(Paths.get(path)));
            int startIndex = fileContent.indexOf(":") + 1;
            String signature = fileContent.substring(startIndex).trim();

            // Hapus semua karakter yang bukan angka dari signature
            signature = signature.replaceAll("[^\\d]", "");

            return signature;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] readMessageFromFile(String path) {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] sha256(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}