import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;

public class criarUser{
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
        String certFile = args[4];

        // criar pasta do utilizador
        try {
            if (Files.exists(Paths.get("serverFiles/" + name))) {
                System.err.println("Error: User already exists.");
                System.exit(1);
            }

            Files.createDirectory(Paths.get("serverFiles/" + name));

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

            // gravar no ficheiro users
            String userLine = name + ":" + role + ":" + saltBase64 + ":" + hashBase64 + "\n";
            Files.write(Paths.get("serverFiles/users"), userLine.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            System.out.println("User " + name + " created successfully.");

        } catch (Exception e) {
            System.err.println("Error creating user: " + e.getMessage());
            System.exit(1);
        }
        
    }
}