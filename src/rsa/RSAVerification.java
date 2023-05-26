/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.swing.JOptionPane;


import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
//import org.apache.poi.hwpf.HWPFDocument;
//import org.apache.poi.hwpf.extractor.WordExtractor;

/**
 *
 * @author Shania
 */


public class RSAVerification {
    //private static final int CERTAINTY = 10;
    //private static final int KEY_LENGTH = 64;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        // Read the encrypted signature from file
        String signatureFilePath = Hal3.tsign.getText();
        String encryptedSignatureText = readSignatureFromFile(signatureFilePath);
        BigInteger encryptedSignature = new BigInteger(removeNonNumericCharacters(encryptedSignatureText));

        // Extract the public key values (e and n)
        String publicKeyText = Halaman1.KPublik.getText();
        String[] publicKeyParts = publicKeyText.replace("(", "").replace(")", "").split(",");
        BigInteger e = new BigInteger(removeNonNumericCharacters(publicKeyParts[0].trim()));
        BigInteger n = new BigInteger(removeNonNumericCharacters(publicKeyParts[1].trim()));

        // Decrypt the signature using the public key
        BigInteger decryptedSignature = encryptedSignature.modPow(e, n);

        // Convert the decrypted signature to byte array
        byte[] decryptedSignatureBytes = decryptedSignature.toByteArray();

        // Remove leading zeros from the decrypted signature
        byte[] trimmedSignatureBytes = removeLeadingZeros(decryptedSignatureBytes);

        // Read the original message from the PDF file
        String filePath = Hal3.tdata.getText();
        byte[] originalMessage = readOriginalMessageFromTXT(filePath);

        // Calculate the hash of the original message
        byte[] originalHash = calculateHash(originalMessage);

        // Compare the trimmed signature and the original hash
        boolean signatureValid = MessageDigest.isEqual(trimmedSignatureBytes, originalHash);
        if (signatureValid) {
            JOptionPane.showMessageDialog(null, "Digital signature valid.", "Valid", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "Digital signature tidak valid.", "Tidak Valid", JOptionPane.ERROR_MESSAGE);
        }

        // Print the verification result
        //System.out.println("Signature Valid: " + signatureValid);
    }

    private static String readSignatureFromFile(String filePath) throws IOException {
        return Files.readString(Paths.get(filePath)).trim();
    }

    private static String removeNonNumericCharacters(String input) {
        return input.replaceAll("[^0-9]", "");
    }

    private static byte[] removeLeadingZeros(byte[] bytes) {
        int firstNonZeroIndex = 0;
        while (firstNonZeroIndex < bytes.length && bytes[firstNonZeroIndex] == 0) {
            firstNonZeroIndex++;
        }
        return java.util.Arrays.copyOfRange(bytes, firstNonZeroIndex, bytes.length);
    }

    private static byte[] readOriginalMessage(String filePath) throws IOException {
        String extension = getFileExtension(filePath);
        if (extension.equalsIgnoreCase("txt")) {
            return readOriginalMessageFromTXT(filePath);
        } else {
            throw new IllegalArgumentException("Unsupported file format");
        }
       /* if (extension.equalsIgnoreCase("pdf")) {
            return readOriginalMessageFromPDF(filePath);
        } else if (extension.equalsIgnoreCase("doc")) {
            return readOriginalMessageFromDOC(filePath);
        } else if (extension.equalsIgnoreCase("txt")) {
            return readOriginalMessageFromTXT(filePath);
        } else {
            throw new IllegalArgumentException("Unsupported file format");
        }*/
    }

/*    private static byte[] readOriginalMessageFromPDF(String filePath) throws IOException {
        PDDocument document = PDDocument.load(new File(filePath));
        PDFTextStripper stripper = new PDFTextStripper();
        String text = stripper.getText(document);
        document.close();
        return text.getBytes();
    }

    private static byte[] readOriginalMessageFromDOC(String filePath) throws IOException {
        FileInputStream fis = new FileInputStream(filePath);
        HWPFDocument document = new HWPFDocument(fis);
        WordExtractor extractor = new WordExtractor(document);
        String text = extractor.getText();
        extractor.close();
        document.close();
        fis.close();
        return text.getBytes();
    }*/

    private static byte[] readOriginalMessageFromTXT(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        return Files.readAllBytes(path);
    }

    private static String getFileExtension(String filePath) {
        int dotIndex = filePath.lastIndexOf(".");
        if (dotIndex > 0 && dotIndex < filePath.length() - 1) {
            return filePath.substring(dotIndex + 1);
        }
        return "";
    }

    private static byte[] calculateHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
