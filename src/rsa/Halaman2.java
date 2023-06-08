/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package rsa;

// HALAMAN TIDAK TERPAKAI

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.StringTokenizer;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author Shania
 */
public class Halaman2 extends javax.swing.JFrame {
    JFileChooser dialog = new JFileChooser();

    /**
     * Creates new form Halaman
     */
    public Halaman2() {
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
        txtPath = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtDisplay = new javax.swing.JTextArea();
        PreviousKey = new javax.swing.JToggleButton();
        Browse = new javax.swing.JButton();
        Display = new javax.swing.JButton();
        NewKey = new javax.swing.JButton();
        ToFrame3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Sources");
        setResizable(false);

        jLabel1.setFont(new java.awt.Font("Sitka Display", 1, 20)); // NOI18N
        jLabel1.setText("Data Sources");

        txtPath.setEditable(false);

        txtDisplay.setEditable(false);
        txtDisplay.setColumns(20);
        txtDisplay.setLineWrap(true);
        txtDisplay.setRows(5);
        jScrollPane1.setViewportView(txtDisplay);

        PreviousKey.setText("Use Previous Key");
        PreviousKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PreviousKeyActionPerformed(evt);
            }
        });

        Browse.setText("Browse File");
        Browse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                BrowseActionPerformed(evt);
            }
        });

        Display.setText("Display Contents");
        Display.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DisplayActionPerformed(evt);
            }
        });

        NewKey.setText("Generate a New Key");
        NewKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NewKeyActionPerformed(evt);
            }
        });

        ToFrame3.setText("Next");
        ToFrame3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ToFrame3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(35, 35, 35)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel1)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(NewKey)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE)
                                .addComponent(txtPath)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 25, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(Browse, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(Display, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addComponent(ToFrame3)
                                .addGap(22, 22, 22))))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(PreviousKey)))
                .addGap(26, 26, 26))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(jLabel1)
                .addGap(30, 30, 30)
                .addComponent(PreviousKey)
                .addGap(15, 15, 15)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Browse)
                    .addComponent(txtPath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(15, 15, 15)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(Display)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 56, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(NewKey)
                    .addComponent(ToFrame3))
                .addGap(42, 42, 42))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void BrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_BrowseActionPerformed
        dialog.setCurrentDirectory(new File("."));
        int pfile = dialog.showOpenDialog(this);
        
        if(pfile == JFileChooser.APPROVE_OPTION){
        File file = dialog.getSelectedFile();
            try {
                txtPath.setText("" +file);
            } catch (Exception e){
                System.out.println("Error :" +e.getMessage());
            }
        }
    }//GEN-LAST:event_BrowseActionPerformed

    private void DisplayActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DisplayActionPerformed
        String p = txtPath.getText();
        File file = new File(p);
        try {
            FileInputStream fs = new FileInputStream(file);
            DataInputStream in = new DataInputStream(fs);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String strline;
            while ((strline = br.readLine())!=null){
            StringTokenizer st = new StringTokenizer(strline,"");
            txtDisplay.setText(txtDisplay.getText()+st.nextToken() + "\n");
            }
            in.close();
        } catch (Exception e){
            System.out.println("Error :" + e.getMessage());    
        }
    }//GEN-LAST:event_DisplayActionPerformed

    private void ToFrame3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ToFrame3ActionPerformed
        if (txtPath.getText().isEmpty()) {
        JOptionPane.showMessageDialog(this, "Silakan Klik Browse File terlebih dahulu.", "Error", JOptionPane.ERROR_MESSAGE);
    } else if (txtDisplay.getText().isEmpty()) {
        JOptionPane.showMessageDialog(this, "Silakan Klik  'Display Contents' terlebih dahulu untuk menampilkan isi file.", "Error", JOptionPane.ERROR_MESSAGE);
    }else{
        Halaman3 hal3 = new Halaman3();
        Halaman3.txtContent.setText(this.txtDisplay.getText());
        hal3.setVisible(true);
        this.dispose();
    }
    }//GEN-LAST:event_ToFrame3ActionPerformed

    private void NewKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NewKeyActionPerformed
        Halaman1 hal1 = new Halaman1();
        hal1.setVisible(true);
        this.dispose();
    }//GEN-LAST:event_NewKeyActionPerformed

    private void PreviousKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PreviousKeyActionPerformed
    if (PreviousKey.isSelected()) {
        String kPrivat = Halaman1.KPrivat.getText();
        Halaman3.bilKey.setText(kPrivat);
        Halaman3.bilKey.setEditable(true);
        Halaman3.bilKey.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                String text = Halaman3.bilKey.getText();
                Halaman3.bilKey.setText(text);
            }
        });
    } else {
        Halaman3.bilKey.setText(null);
        Halaman3.bilKey.setEditable(false);
        Halaman3.bilKey.removeKeyListener(Halaman3.bilKey.getKeyListeners()[0]);
    }
    }//GEN-LAST:event_PreviousKeyActionPerformed

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
            java.util.logging.Logger.getLogger(Halaman2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Halaman2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Halaman2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Halaman2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Halaman2().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Browse;
    private javax.swing.JButton Display;
    private javax.swing.JButton NewKey;
    public static javax.swing.JToggleButton PreviousKey;
    private javax.swing.JButton ToFrame3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    public static javax.swing.JTextArea txtDisplay;
    public static javax.swing.JTextField txtPath;
    // End of variables declaration//GEN-END:variables
}
