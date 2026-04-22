import java.util.Scanner;
import java.util.List;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class criarUser{
    private static final String USERS_FILE = "serverFiles/users";
    private static final String MAC_FILE = "serverFiles/mySaude.mac";
    private static final String KEY = "passMAC";

    public static void main(String[] args) {
        //verificar nr de argumentos
        if(args.length != 5){
            System.err.println("Usage: criarUser <username> <role> <password> -f <file with the user certificate>");
            System.exit(1);
        }

        // inicio autenticação do servidor usando MAC
        try{
            Scanner scanner = new Scanner(System.in);
            System.out.print("Insert MAC password for server operations: ");
            String macPassword = scanner.nextLine();

            // Calcular MAC com a password inserida
            String macCalculado = mySaudeServer.calcularMAC("serverFiles/users", macPassword);

            // Ler o MAC armazenado no ficheiro
            String macArmazenado = Files.readString(Paths.get("serverFiles/mySaude.mac")).trim();
                
            if (!macCalculado.equals(macArmazenado)) {
                System.out.println("ERRO: mac não corresponde!");
                System.exit(1); 
            }
            
            System.out.println("✓ Verificação de integridade OK");
            
        } catch (Exception e) {
            System.err.println("Erro durante autenticação do servidor: " + e.getMessage());
            System.exit(1);
        }

        String name = args[0];
        String role = args[1];
        String password = args[2];
        String certFile = "keys/" + args[4];

        try {
            // ========== FASE 1: VALIDAÇÕES ==========
            
            // Validar se o ficheiro de certificado existe
            if (!Files.exists(Paths.get(certFile))) {
                throw new IllegalArgumentException("Ficheiro de certificado não encontrado: " + certFile);
            }
            
            // Validar se o utilizador já existe no ficheiro users
            if (userExists(name)) {
                throw new IllegalArgumentException("Utilizador já existe no ficheiro users");
            }
            
            // Validar se a pasta do utilizador já existe
            Path userDir = Paths.get("serverFiles/" + name);
            if (Files.exists(userDir)) {
                throw new IllegalArgumentException("Pasta do utilizador já existe");
            }
            
            // Validar o keystore
            validateAndCreateKeystore();
            
            // Gerar dados do utilizador
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hash = md.digest(password.getBytes("UTF-8"));

            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);
            
            // ========== FASE 2: AÇÕES ==========
            
            // 1. Criar pasta do utilizador
            Files.createDirectory(userDir);
            
            try {
                // 2. Adicionar utilizador ao ficheiro
                addUserToFile(name, role, saltBase64, hashBase64);
                
                try {
                    // 3. Importar certificado
                    importCertificateToKeystore(name, certFile);
                    
                    // 4. Atualizar o MAC do ficheiro users
                    String macCalculado = mySaudeServer.calcularMAC("serverFiles/users", KEY);
                    Files.writeString(Paths.get(MAC_FILE), macCalculado);
                    
                    System.out.println("Utilizador " + name + " criado com sucesso.");
                    
                } catch (Exception e) {
                    // Reverter: remover utilizador do ficheiro
                    removeUserFromFile(name);
                    throw new Exception("Erro ao importar certificado: " + e.getMessage());
                }
            } catch (Exception e) {
                // Reverter: remover pasta
                Files.deleteIfExists(userDir);
                throw e;
            }

        } catch (Exception e) {
            System.err.println("Erro ao criar utilizador: " + e.getMessage());
            System.exit(1);
        }
        
    }

    static void importCertificateToKeystore(String username, String certFile) 
            throws Exception {
        // Usar keytool em Java: ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder(
            "keytool", "-importcert", "-noprompt",
            "-alias", username,
            "-file", certFile,
            "-keystore", "serverFiles/keystore.users",
            "-storepass", "passUsers"  // Password da keystore
        );
        
        Process p = pb.start();
        
        // Capturar stderr para debug
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        String errorLine;
        StringBuilder errorOutput = new StringBuilder();
        while ((errorLine = errorReader.readLine()) != null) {
            errorOutput.append(errorLine).append("\n");
        }
        
        int result = p.waitFor();
        
        if (result != 0) {
            throw new Exception("Erro ao importar certificado: " + errorOutput.toString());
        }
        
        System.out.println("Certificado de " + username + " importado");
    }
    
    static void validateAndCreateKeystore() throws Exception {
        Path keystorePath = Paths.get("serverFiles/keystore.users");
        
        // Se o keystore não existe ou está vazio, criar
        if (!Files.exists(keystorePath) || Files.size(keystorePath) == 0) {
            // Deletar o arquivo vazio se existir
            if (Files.exists(keystorePath)) {
                Files.delete(keystorePath);
            }
            
            ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkey", "-noprompt",
                "-alias", "server",
                "-keystore", "serverFiles/keystore.users",
                "-storepass", "passUsers",
                "-keypass", "passUsers",
                "-dname", "CN=MySaudeServer,O=MySaude,C=PT",
                "-validity", "365",
                "-keyalg", "RSA",
                "-keysize", "2048"
            );
            
            Process p = pb.start();
            
            // Capturar erro
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            String errorLine;
            StringBuilder errorOutput = new StringBuilder();
            while ((errorLine = errorReader.readLine()) != null) {
                errorOutput.append(errorLine).append("\n");
            }
            
            int result = p.waitFor();
            
            if (result != 0) {
                throw new Exception("Erro ao criar keystore: " + errorOutput.toString());
            }
            
            System.out.println("Keystore criado com sucesso");
        }
    } 

    static void addUserToFile(String username, String funcao, 
                             String salt, String digest) throws IOException {
        try (FileWriter fw = new FileWriter(USERS_FILE, true)) {
            fw.write(username + ":" + funcao + ":" + salt + ":" + digest + "\n");
        }
    }
    
    static void removeUserFromFile(String username) throws IOException {
        // Ler o ficheiro
        java.util.List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
        
        // Remover a linha do utilizador
        lines.removeIf(line -> line.startsWith(username + ":"));
        
        // Reescrever o ficheiro
        Files.write(Paths.get(USERS_FILE), lines);
    }

    static boolean userExists(String username) {
        // Verificar no ficheiro users
        try (BufferedReader br = new BufferedReader(new FileReader(USERS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length > 0 && parts[0].equals(username)) {
                    return true;
                }
            }
        } catch (IOException e) {}
        return false;
    }

}