import java.io.*;
import java.nio.file.*;

/**
 * YA ESYA PARTE FOI AI FODAM-SE RAH
 * Creates the directory: serverFiles/<username>
 * This must be run on the server machine before the user can receive files.
 */
// TER CUIDADO AO CRIAR USERS PARA NAO SEREM IGUAIS E TEREM PASSES IGUAIS Q ISTO FODE TUDO
public class criarUser {

    public static void main(String[] args) {
        // explica o comando ao utilizador se este não souber 
        if (args.length < 1) {
            System.err.println("Usage: criarUser <username> [username2 ...]");
            System.exit(1);
        }

        for (String username : args) {
            createUser(username);
        }
    }
    // cria um user e o seu diretorio de envio e recebimento de ficheiros feitos pelo o programa
    private static void createUser(String username) {
        if (username == null || username.trim().isEmpty()) {
            System.err.println("Error: Username cannot be empty.");
            return;
        }

        File serverRoot = new File("serverFiles");
        File userDir = new File(serverRoot, username);

        if (userDir.mkdirs()) {
            System.out.println("User '" + username + "' created successfully (directory: " + userDir.getPath() + ")");
        } else {
            System.err.println("Error: Could not create directory for user '" + username + "'.");
        }
    }
}
