import java.io.*;
import java.nio.file.*;

/**
 * criarUser - Creates a user directory on the server.
 *
 * Usage: criarUser <username>
 *
 * Creates the directory: serverFiles/<username>
 * This must be run on the server machine before the user can receive files.
 */
public class criarUser {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: criarUser <username> [username2 ...]");
            System.exit(1);
        }

        for (String username : args) {
            createUser(username);
        }
    }

    private static void createUser(String username) {
        if (username == null || username.trim().isEmpty()) {
            System.err.println("Error: Username cannot be empty.");
            return;
        }

        // Sanitize username to prevent path traversal
        if (username.contains("..") || username.contains("/") || username.contains("\\")) {
            System.err.println("Error: Invalid username '" + username + "'.");
            return;
        }

        File serverRoot = new File("serverFiles");
        File userDir = new File(serverRoot, username);

        if (userDir.exists()) {
            System.out.println("User '" + username + "' already exists (directory: " + userDir.getPath() + ")");
            return;
        }

        if (userDir.mkdirs()) {
            System.out.println("User '" + username + "' created successfully (directory: " + userDir.getPath() + ")");
        } else {
            System.err.println("Error: Could not create directory for user '" + username + "'.");
        }
    }
}
