/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package rsa;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author Shania
 */
public class Hal2 extends javax.swing.JFrame {

    /**
     * Creates new form Hal2
     */
    public Hal2() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        txtPATH = new javax.swing.JTextField();
        LoadData = new javax.swing.JButton();
        PrevKey = new javax.swing.JToggleButton();
        NewKey = new javax.swing.JButton();
        Sign = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Sources");
        setIconImage(new javax.swing.ImageIcon(getClass().getResource("/image/logo6.png")).getImage());
        setResizable(false);

        jLabel1.setFont(new java.awt.Font("Sitka Display", 1, 20)); // NOI18N
        jLabel1.setText("Data Sources");

        txtPATH.setEditable(false);

        LoadData.setText("Load Data");
        LoadData.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LoadDataActionPerformed(evt);
            }
        });

        PrevKey.setText("Use Previous Key");
        PrevKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PrevKeyActionPerformed(evt);
            }
        });

        NewKey.setText("Generate a New Key");
        NewKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NewKeyActionPerformed(evt);
            }
        });

        Sign.setText("Signing");
        Sign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SignActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(PrevKey)
                .addGap(18, 18, 18))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(38, 38, 38)
                        .addComponent(NewKey))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(186, 186, 186)
                        .addComponent(jLabel1)
                        .addGap(28, 28, 28)
                        .addComponent(Sign, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(32, 32, 32)
                        .addComponent(txtPATH, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(11, 11, 11)
                        .addComponent(LoadData, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(18, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(jLabel1)
                .addGap(76, 76, 76)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtPATH, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(LoadData))
                .addGap(18, 18, 18)
                .addComponent(PrevKey)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 163, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(NewKey)
                    .addComponent(Sign))
                .addGap(31, 31, 31))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void LoadDataActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LoadDataActionPerformed
        JFileChooser dialog = new JFileChooser();
        dialog.setCurrentDirectory(new File("C:\\Users\\Shania\\OneDrive\\Documents\\NetBeansProjects\\satu\\hasil\\sources"));
        int result = dialog.showOpenDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = dialog.getSelectedFile();
            try {
                String filePath = file.getAbsolutePath();
                txtPATH.setText(filePath);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Terjadi kesalahan saat memilih file:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                e.printStackTrace();
            }
        }
    }//GEN-LAST:event_LoadDataActionPerformed

    private void NewKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NewKeyActionPerformed
        Halaman1 hal1 = new Halaman1();
        hal1.setVisible(true);
        this.dispose();
    }//GEN-LAST:event_NewKeyActionPerformed

    private void PrevKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PrevKeyActionPerformed
        if(PrevKey.isSelected()){
            String privateKey = Halaman1.KPrivat.getText();
        } else{
            JOptionPane.showMessageDialog(this, "Tombol belum diaktifkan!", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_PrevKeyActionPerformed

    private void SignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SignActionPerformed
    if (txtPATH.getText().isEmpty()) {
        JOptionPane.showMessageDialog(this, "Pilih file terlebih dahulu.", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }else if (!PrevKey.isSelected()) {
        JOptionPane.showMessageDialog(this, "Klik tombol Previous Key terlebih dahulu.", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }else{
       try {
            RSA.main(new String[]{});   
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Halaman1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Hal2.class.getName()).log(Level.SEVERE, null, ex);
        }
       JOptionPane.showMessageDialog(this, "Digital Signature tersimpan ke dalam file", "Info", JOptionPane.INFORMATION_MESSAGE);
        this.dispose();
    }
            Halaman3Lain hal3 = new Halaman3Lain();
            hal3.setVisible(true);
            this.setVisible(false);
            
            /*Hal3Lain hal3 = new Hal3Lain();
            hal3.setVisible(true);
            this.setVisible(false);*/
    }//GEN-LAST:event_SignActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Hal2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Hal2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Hal2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Hal2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Hal2().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton LoadData;
    private javax.swing.JButton NewKey;
    private javax.swing.JToggleButton PrevKey;
    private javax.swing.JButton Sign;
    private javax.swing.JLabel jLabel1;
    public static javax.swing.JTextField txtPATH;
    // End of variables declaration//GEN-END:variables
}
