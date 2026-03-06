import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class VirusVania extends JFrame {
    private JTextArea logArea;
    private JTable threatTable;
    private DefaultTableModel tableModel;
    private JButton scanButton, quarantineButton, stopButton;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    
    private VirusDatabase virusDB;
    private QuarantineManager quarantine;
    private ExecutorService executor;
    private volatile boolean scanning = false;
    
    public VirusVania() {
        virusDB = new VirusDatabase();
        quarantine = new QuarantineManager();
        initializeUI();
    }
    
    private void initializeUI() {
        setTitle("Java Antivirus Scanner");
        setSize(900, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));
        
        // Top panel with controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        scanButton = new JButton("Scan Directory");
        stopButton = new JButton("Stop Scan");
        quarantineButton = new JButton("View Quarantine");
        JButton updateDBButton = new JButton("Update Signatures");
        
        stopButton.setEnabled(false);
        
        topPanel.add(scanButton);
        topPanel.add(stopButton);
        topPanel.add(quarantineButton);
        topPanel.add(updateDBButton);
        
        // Progress panel
        JPanel progressPanel = new JPanel(new BorderLayout(5, 5));
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        statusLabel = new JLabel("Ready to scan");
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(statusLabel, BorderLayout.SOUTH);
        
        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(topPanel, BorderLayout.NORTH);
        topContainer.add(progressPanel, BorderLayout.SOUTH);
        
        // Threat table
        String[] columns = {"File Path", "Threat Type", "Severity", "Detection Method"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        threatTable = new JTable(tableModel);
        JScrollPane tableScroll = new JScrollPane(threatTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Detected Threats"));
        
        // Log area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Scan Log"));
        
        // Split pane for table and log
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
            tableScroll, logScroll);
        splitPane.setDividerLocation(250);
        
        add(topContainer, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        
        // Event handlers
        scanButton.addActionListener(e -> startScan());
        stopButton.addActionListener(e -> stopScan());
        quarantineButton.addActionListener(e -> showQuarantine());
        updateDBButton.addActionListener(e -> updateSignatures());
        
        setLocationRelativeTo(null);
    }
    
    private void startScan() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedDir = chooser.getSelectedFile();
            tableModel.setRowCount(0);
            logArea.setText("");
            
            scanning = true;
            scanButton.setEnabled(false);
            stopButton.setEnabled(true);
            
            executor = Executors.newSingleThreadExecutor();
            executor.submit(() -> performScan(selectedDir));
        }
    }
    
    private void stopScan() {
        scanning = false;
        if (executor != null) {
            executor.shutdownNow();
        }
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Scan stopped by user");
            scanButton.setEnabled(true);
            stopButton.setEnabled(false);
        });
    }
    
    private void performScan(File directory) {
        try {
            List<File> files = new ArrayList<>();
            collectFiles(directory, files);
            
            final int total = files.size();
            int scannedCount = 0;
            
            log("Starting scan of " + total + " files...\n");
            
            for (File file : files) {
                if (!scanning) break;
                
                scannedCount++;
                int progress = (scannedCount * 100) / total;
                updateProgress(progress, "Scanning: " + file.getName());
                
                scanFile(file);
                Thread.sleep(10); // Simulate processing time
            }
            
            final int finalScanned = scannedCount;
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("Scan complete! Scanned " + finalScanned + " files");
                scanButton.setEnabled(true);
                stopButton.setEnabled(false);
                progressBar.setValue(100);
            });
            
            log("\nScan completed. " + tableModel.getRowCount() + " threats detected.\n");
            
        } catch (Exception e) {
            log("Error during scan: " + e.getMessage() + "\n");
        }
    }
    
    private void collectFiles(File dir, List<File> files) {
        if (!dir.isDirectory()) return;
        
        File[] fileList = dir.listFiles();
        if (fileList == null) return;
        
        for (File file : fileList) {
            if (!scanning) break;
            
            if (file.isDirectory()) {
                collectFiles(file, files);
            } else {
                files.add(file);
            }
        }
    }
    
    private void scanFile(File file) {
        try {
            // Skip very large files (>100MB) in this demo
            if (file.length() > 100_000_000) {
                return;
            }
            
            // Signature-based detection
            String fileHash = calculateMD5(file);
            if (virusDB.isKnownThreat(fileHash)) {
                String threatName = virusDB.getThreatName(fileHash);
                addThreat(file.getAbsolutePath(), threatName, "High", "Signature");
                log("[THREAT] " + file.getName() + " - " + threatName + "\n");
                return;
            }
            
            // Heuristic analysis
            String heuristicThreat = performHeuristicAnalysis(file);
            if (heuristicThreat != null) {
                addThreat(file.getAbsolutePath(), heuristicThreat, "Medium", "Heuristic");
                log("[SUSPICIOUS] " + file.getName() + " - " + heuristicThreat + "\n");
            }
            
        } catch (Exception e) {
            // Skip files that can't be read
        }
    }
    
    private String calculateMD5(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private String performHeuristicAnalysis(File file) {
        try {
            String fileName = file.getName().toLowerCase();
            String content = "";
            
            // Read file content (limit to first 10KB for analysis)
            if (file.length() < 10000) {
                content = new String(Files.readAllBytes(file.toPath())).toLowerCase();
            }
            
            // Suspicious file extensions
            if (fileName.endsWith(".exe.txt") || fileName.endsWith(".scr") || 
                fileName.contains("..")) {
                return "Suspicious File Extension";
            }
            
            // Check for suspicious patterns in scripts
            if (fileName.endsWith(".bat") || fileName.endsWith(".cmd") || 
                fileName.endsWith(".ps1") || fileName.endsWith(".vbs")) {
                
                if (content.contains("format c:") || content.contains("del /f /s /q")) {
                    return "Potentially Destructive Script";
                }
                if (content.contains("powershell") && content.contains("downloadstring")) {
                    return "Suspicious PowerShell Download";
                }
            }
            
            // Check for encoded/obfuscated content
            if (content.length() > 100) {
                int base64Chars = 0;
                for (char c : content.toCharArray()) {
                    if (Character.isLetterOrDigit(c) || c == '+' || c == '/' || c == '=') {
                        base64Chars++;
                    }
                }
                if ((base64Chars * 100 / content.length()) > 90) {
                    return "Highly Encoded Content";
                }
            }
            
        } catch (Exception e) {
            // Skip analysis errors
        }
        
        return null;
    }
    
    private void addThreat(String path, String type, String severity, String method) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{path, type, severity, method});
        });
    }
    
    private void updateProgress(int value, String status) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(value);
            statusLabel.setText(status);
        });
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    private void showQuarantine() {
        JDialog dialog = new JDialog(this, "Quarantine Manager", true);
        dialog.setSize(600, 400);
        dialog.setLayout(new BorderLayout());
        
        JTextArea quarantineArea = new JTextArea();
        quarantineArea.setEditable(false);
        quarantineArea.setText(quarantine.listQuarantined());
        
        dialog.add(new JScrollPane(quarantineArea), BorderLayout.CENTER);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    private void updateSignatures() {
        virusDB.addTestSignatures();
        JOptionPane.showMessageDialog(this, 
            "Virus signatures updated!\nTotal signatures: " + virusDB.getSignatureCount(),
            "Update Complete", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    // Inner class for virus database
    static class VirusDatabase {
        private Map<String, String> signatures;
        
        public VirusDatabase() {
            signatures = new HashMap<>();
            addTestSignatures();
        }
        
        public void addTestSignatures() {
            // Example malware signatures (these are fictional for demo purposes)
            signatures.put("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File");
            signatures.put("275a021bbfb6489e54d471899f7db9d1", "Generic.Trojan");
            signatures.put("3395856ce81f2b7382dee72602f798b6", "Backdoor.Agent");
            signatures.put("5d41402abc4b2a76b9719d911017c592", "Test.Malware");
        }
        
        public boolean isKnownThreat(String hash) {
            return signatures.containsKey(hash);
        }
        
        public String getThreatName(String hash) {
            return signatures.getOrDefault(hash, "Unknown Threat");
        }
        
        public int getSignatureCount() {
            return signatures.size();
        }
    }
    
    // Inner class for quarantine management
    static class QuarantineManager {
        private List<String> quarantinedFiles;
        
        public QuarantineManager() {
            quarantinedFiles = new ArrayList<>();
        }
        
        public void quarantine(String filePath) {
            quarantinedFiles.add(filePath);
        }
        
        public String listQuarantined() {
            if (quarantinedFiles.isEmpty()) {
                return "No files in quarantine.";
            }
            
            StringBuilder sb = new StringBuilder("Quarantined Files:\n\n");
            for (int i = 0; i < quarantinedFiles.size(); i++) {
                sb.append((i + 1)).append(". ").append(quarantinedFiles.get(i)).append("\n");
            }
            return sb.toString();
        }
    }
    
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            VirusVania scanner = new VirusVania();
            scanner.setVisible(true);
        });
    }
}