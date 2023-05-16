/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rsa;

/**
 *
 * @author Shania
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.swing.JOptionPane;

public class VerifyRSA {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String fileName = "Digital_Signature.txt";

        // read digital signature and public key from file
        String digitalSignatureString = "";
        String publicKeyString = "";
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line = reader.readLine();
            while (line != null) {
                if (line.startsWith("Digital Signature: ")) {
                    digitalSignatureString = line.substring("Digital Signature: ".length());
                }
                if (line.startsWith("Public Key (e,n): ")) {
                    publicKeyString = line.substring("Public Key (e,n): ".length());
                }
                line = reader.readLine();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        // parse digital signature and public key
        BigInteger digitalSignature = new BigInteger(digitalSignatureString);
        String[] publicKeyParts = publicKeyString.split(",");
        BigInteger e = new BigInteger(publicKeyParts[0].trim());
        BigInteger n = new BigInteger(publicKeyParts[1].trim());

        // hash message
        String message = Halaman3.txtContent.getText();
        byte[] hash = sha256(message.getBytes(StandardCharsets.UTF_8));

        // verify digital signature
        BigInteger decryptedHash = digitalSignature.modPow(e, n);
        if (new BigInteger(hash).equals(decryptedHash)) {
            //System.out.println("Digital signature is valid.");
            JOptionPane.showMessageDialog(null, "Digital signature is valid.", "Info", JOptionPane.INFORMATION_MESSAGE);
            // jika digital signature valid, maka pindah ke halaman verifikasi
            Valid hal5 = new Valid();
            hal5.setVisible(true);
        } else {
            //System.out.println("Digital signature is invalid.");
            JOptionPane.showMessageDialog(null, "Digital signature is invalid.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static byte[] sha256(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }
}
