import java.io.*;
import java.net.*;

// comando para inicializar : java mySaudeServer <porto>
public class mySaudeServer {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: mySaudeServer <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);
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
            String command = in.readUTF();

            if (command.equals("SEND")) {
                handleSend(in, out);
            } else if (command.equals("RECEIVE")) {
                handleReceive(in, out);
            } else {
                out.writeUTF("ERROR: Unknown command");
                out.flush();
            }

        } catch (IOException e) {
            System.err.println("Client handling error: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private void handleSend(DataInputStream in, DataOutputStream out) throws IOException {
        String targetUser = in.readUTF();
        File userDir = new File("serverFiles" + File.separator + targetUser);

        int fileCount = in.readInt();

        for (int i = 0; i < fileCount; i++) {
            String filename = in.readUTF();

            // Diretoria do utilizador tem de existir
            if (!userDir.exists() || !userDir.isDirectory()) {
                out.writeUTF("ERROR: User directory does not exist for user '" + targetUser + "'");
                out.flush();

                long fileSize = in.readLong();
                in.skipNBytes(fileSize);
                continue;
            }

            File destFile = new File(userDir, filename);

            // Já existe o ficheiro com o mesmo nome
            if (destFile.exists()) {
                out.writeUTF("ERROR: File '" + filename + "' already exists on server for user '" + targetUser + "'");
                out.flush();

                long fileSize = in.readLong();
                in.skipNBytes(fileSize);
                continue;
            }

            if (violatesUniqueness(userDir, filename)) {
                out.writeUTF("ERROR: A variant of this file already exists on server (pdf/cifrado/assinado/envelope).");
                out.flush();

                long fileSize = in.readLong();
                in.skipNBytes(fileSize);
                continue;
            }

            // Pre-check OK
            out.writeUTF("OK");
            out.flush();

            // Receber o ficheiro
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
                out.flush();
                continue;
            }

            System.out.println("Received file '" + filename + "' for user '" + targetUser + "'");
            out.writeUTF("OK");
            out.flush();
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

            if (!userDir.exists() || !userDir.isDirectory()) {
                out.writeUTF("ERROR: User directory does not exist for user '" + username + "'");
                out.flush();
                continue;
            }

            File srcFile = new File(userDir, filename);

            if (!srcFile.exists() || !srcFile.isFile()) {
                out.writeUTF("ERROR: File '" + filename + "' does not exist on server for user '" + username + "'");
                out.flush();
                continue;
            }

            out.writeUTF("OK");
            out.flush();

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

    private static String baseNameForUniqueness(String filename) {
        if (filename.endsWith(".cifrado"))  return filename.substring(0, filename.length() - ".cifrado".length());
        if (filename.endsWith(".assinado")) return filename.substring(0, filename.length() - ".assinado".length());
        if (filename.endsWith(".envelope")) return filename.substring(0, filename.length() - ".envelope".length());
        return filename; 
    }

    /**
     * Devolve true se já existir no diretório do utilizador alguma variante do mesmo "base"
     * (base, base.cifrado, base.assinado, base.envelope), EXCLUINDO o próprio incomingName.
     * O caso "incomingName já existe" é tratado antes (destFile.exists()).
     */
    private static boolean violatesUniqueness(File userDir, String incomingName) {
        String base = baseNameForUniqueness(incomingName);

        String[] variants = new String[] {
            base,
            base + ".cifrado",
            base + ".assinado",
            base + ".envelope"
        };

        for (String v : variants) {
            if (v.equals(incomingName)) continue; 
            File f = new File(userDir, v);
            if (f.exists()) return true;
        }
        return false;
    }
}