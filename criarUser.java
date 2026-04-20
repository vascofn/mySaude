import java.util.Scanner;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;

public class criarUser{
    private static final String USERS_FILE = "serverFiles/users";

    public static void main(String[] args) {
        //verificar nr de argumentos
        if(args.length != 5){
            System.err.println("Usage: criarUser <username> <role> <password> -f <file with the user certificate>");
            System.exit(1);
        }


        // // inicio autenticação do servidor usando MAC
        // try{
        //     Scanner scanner = new Scanner(System.in);
        //     System.out.print("Insert MAC password for server operations: ");
        //     String macPassword = scanner.nextLine();

        //     byte[] pass = macPassword.getBytes();
        //     SecretKey key = new SecretKeySpec(pass, 0, pass.length, "HmacSHA256");

        //     String macCalculado = calcularMAC("users", key);

        //     String macArmazenado = Files.readString(Paths.get("mySaude.mac"));
                
        //     if (!macCalculado.equals(macArmazenado)) {
        //         System.out.println("ERRO: Ficheiro de passwords foi modificado!");
        //         System.out.println("MAC esperado: " + macArmazenado);
        //         System.out.println("MAC calculado: " + macCalculado);
        //         System.exit(1); 
        //     }
            
        //     System.out.println("✓ Verificação de integridade OK");
        //      
        // } catch (Exception e) {
        //     System.err.println("Erro durante autenticação do servidor: " + e.getMessage());
        //     System.exit(1);
        // }

        String name = args[0];
        String role = args[1];
        String password = args[2];
        String certFile = "keys/" + args[4];

        try {
            Path userDir = Paths.get("serverFiles/" + name);

            if (userExists(name)) {
                throw new IllegalArgumentException("Error: User already exists in users file.");
            }

            if (Files.exists(userDir)) {
                System.err.println("Error: User already exists.");
                System.exit(1);
            }

            Files.createDirectory(userDir);

            // gerar salt aleatório
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            // hash da password com SHA-256 e salt
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hash = md.digest(password.getBytes("UTF-8"));

            // codificar salt e hash em base64
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            addUserToFile(name, role, saltBase64, hashBase64);
            importCertificateToKeystore(name, certFile);

            System.out.println("User " + name + " created successfully.");

        } catch (Exception e) {
            System.err.println("Error creating user: " + e.getMessage());
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
        int result = p.waitFor();
        
        if (result != 0) {
            System.err.println("Erro ao importar certificado para keystore");
            System.exit(1);
        }
        
        System.out.println("Certificado de " + username + " importado");
    } 

    static void addUserToFile(String username, String funcao, 
                             String salt, String digest) throws IOException {
        try (FileWriter fw = new FileWriter(USERS_FILE, true)) {
            fw.write(username + ":" + funcao + ":" + salt + ":" + digest + "\n");
        }
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