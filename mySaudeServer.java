import java.io.*;
import java.net.*;
import java.nio.file.*;

public class mySaudeServer {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: mySaudeServer <port>");
            System.exit(1);
        }

        int port;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number.");
            System.exit(1);
            return;
        }

        System.out.println("mySaudeServer starting on port " + port + "...");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server listening on port " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New connection from " + clientSocket.getInetAddress());
                Thread clientThread = new Thread(new ClientHandler(clientSocket));
                clientThread.start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            System.exit(1);
        }
    }
}

class ClientHandler implements Runnable {

    private final Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream())
        ) {
            // Read command: SEND or RECEIVE
            String command = in.readUTF();

            if (command.equals("SEND")) {
                handleSend(in, out);
            } else if (command.equals("RECEIVE")) {
                handleReceive(in, out);
            } else {
                out.writeUTF("ERROR: Unknown command");
            }

        } catch (IOException e) {
            System.err.println("Client handling error: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Handle SEND command: client sends files to a target user's directory.
     * Protocol:
     *   Client -> Server: "SEND"
     *   Client -> Server: targetUsername (String)
     *   Client -> Server: number of files (int)
     *   For each file:
     *     Client -> Server: filename (String)
     *     Server -> Client: "OK" or "ERROR: <reason>"  (pre-check)
     *     If OK:
     *       Client -> Server: file size (long)
     *       Client -> Server: file bytes
     *       Server -> Client: "OK" or "ERROR: <reason>"
     */
    private void handleSend(DataInputStream in, DataOutputStream out) throws IOException {
        String targetUser = in.readUTF();
        File userDir = new File("serverFiles" + File.separator + targetUser);

        int fileCount = in.readInt();

        for (int i = 0; i < fileCount; i++) {
            String filename = in.readUTF();

            // Check if user directory exists
            if (!userDir.exists()) {
                out.writeUTF("ERROR: User directory does not exist for user '" + targetUser + "'");
                // Still need to drain the file from the stream
                long fileSize = in.readLong();
                in.skipNBytes(fileSize);
                continue;
            }

            File destFile = new File(userDir, filename);

            // Check if file already exists
            if (destFile.exists()) {
                out.writeUTF("ERROR: File '" + filename + "' already exists on server for user '" + targetUser + "'");
                long fileSize = in.readLong();
                in.skipNBytes(fileSize);
                continue;
            }

            // All pre-checks passed
            out.writeUTF("OK");

            // Receive file
            long fileSize = in.readLong();
            byte[] buffer = new byte[8192];
            long remaining = fileSize;

            try (FileOutputStream fos = new FileOutputStream(destFile)) {
                while (remaining > 0) {
                    int toRead = (int) Math.min(buffer.length, remaining);
                    int read = in.read(buffer, 0, toRead);
                    if (read == -1) break;
                    fos.write(buffer, 0, read);
                    remaining -= read;
                }
            } catch (IOException e) {
                out.writeUTF("ERROR: Failed to write file on server: " + e.getMessage());
                continue;
            }

            System.out.println("Received file '" + filename + "' for user '" + targetUser + "'");
            out.writeUTF("OK");
        }
    }

    /**
     * Handle RECEIVE command: client requests files from their own directory.
     * Protocol:
     *   Client -> Server: "RECEIVE"
     *   Client -> Server: username (String)
     *   Client -> Server: number of files (int)
     *   For each file:
     *     Client -> Server: filename (String)
     *     Server -> Client: "OK" or "ERROR: <reason>"
     *     If OK:
     *       Server -> Client: file size (long)
     *       Server -> Client: file bytes
     */
    private void handleReceive(DataInputStream in, DataOutputStream out) throws IOException {
        String username = in.readUTF();
        File userDir = new File("serverFiles" + File.separator + username);

        int fileCount = in.readInt();

        for (int i = 0; i < fileCount; i++) {
            String filename = in.readUTF();

            if (!userDir.exists()) {
                out.writeUTF("ERROR: User directory does not exist for user '" + username + "'");
                continue;
            }

            File srcFile = new File(userDir, filename);

            if (!srcFile.exists()) {
                out.writeUTF("ERROR: File '" + filename + "' does not exist on server for user '" + username + "'");
                continue;
            }

            out.writeUTF("OK");

            // Send file
            long fileSize = srcFile.length();
            out.writeLong(fileSize);

            byte[] buffer = new byte[8192];
            try (FileInputStream fis = new FileInputStream(srcFile)) {
                int read;
                while ((read = fis.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }

            out.flush();
            System.out.println("Sent file '" + filename + "' to user '" + username + "'");
        }
    }
}
