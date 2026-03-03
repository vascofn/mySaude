import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;


//classe que age como cliente do servidor mySaude
public class mySaude {

    public static void main(String[] args) {
        if (args.length < 4) {
            printUsage();
            System.exit(1);
        }

        // Parse arguments
        Map<String, List<String>> params = parseArgs(args);

        if (params == null) {
            printUsage();
            System.exit(1);
        }

        String serverAddress = getParam(params, "-s");
        String username = getParam(params, "-u");

        if (serverAddress == null || username == null) {
            System.err.println("Error: -s and -u are required.");
            printUsage();
            System.exit(1);
        }

        // Parse server address
        String[] serverParts = serverAddress.split(":");
        if (serverParts.length != 2) {
            System.err.println("Error: Server address must be in format address:port");
            System.exit(1);
        }
        
        String host = serverParts[0]; // o hosto vamos ser sempre nos nas nossas maquinas pori isso ns pq que a stora n deixou que pusessemos isto como variavel global
        int port;
        try {
            port = Integer.parseInt(serverParts[1]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number.");
            System.exit(1);
            return;
        }

        // dita a operacao q fazemos
        if (params.containsKey("-e")) {
            // Send files
            List<String> files = params.get("-e");
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (target username) is required with -e");
                System.exit(1);
            }
            sendFiles(host, port, username, targetUser, files);

        } else if (params.containsKey("-r")) {
            // Receive files
            List<String> files = params.get("-r");
            receiveFiles(host, port, username, files);

        } else {
            System.err.println("Error: Must specify -e or -r option.");
            printUsage();
            System.exit(1);
        }
    }

    // metodo usado em cima que mandao os ficheiros pra o server
    private static void sendFiles(String host, int port, String username,
                                   String targetUser, List<String> filenames) {

        List<File> validFiles = new ArrayList<>();
        List<String> validNames = new ArrayList<>();
        // ve se os ficheiros que queremos mandar existem e se são mesmo ficheiros 
        for (String filename : filenames) {
        Path susrDir = Paths.get("serverFiles", username, filename);
        File f = new File(filename);
            if (!Files.exists(susrDir)) {
                System.err.println("Error: File '" + filename + "' does not exist in the " + username +" directory. Impossible to send a file that doesnt exist");
                return;
            } else if (!f.isFile()) {
                System.err.println("Error: '" + filename + "' is not a regular file. Skipping.");
            } else {
                validFiles.add(f);
                validNames.add(f.getName());
            }
        }

        if (validFiles.isEmpty()) {
            System.out.println("No valid files to send.");
            return;
        }

        try (
            Socket socket = new Socket(host, port);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream())
        ) {
            // Send command
            out.writeUTF("SEND");
            out.writeUTF(targetUser);
            out.writeInt(validFiles.size());

            for (int i = 0; i < validFiles.size(); i++) {
                File file = validFiles.get(i);
                String name = validNames.get(i);

                out.writeUTF(name);

                // Check server pre-response (server may reject before we send data)
                // Server expects us to always send the file, so we send it regardless
                // Actually our protocol: server gives OK/ERROR after filename,
                // then if OK we send data. But server also needs to drain if ERROR.
                // Revised: We always send file size + data; server drains if needed.

                // Send file size + data
                long fileSize = file.length();
                out.writeLong(fileSize);

                byte[] buffer = new byte[8192];
                try (FileInputStream fis = new FileInputStream(file)) {
                    int read;
                    while ((read = fis.read(buffer)) != -1) {
                        out.write(buffer, 0, read);
                    }
                }
                out.flush();

                // Read server response
                String response = in.readUTF();
                if (response.startsWith("ERROR")) {
                    System.err.println("Error sending '" + name + "': " + response);
                } else {
                    System.out.println("File '" + name + "' sent successfully to user '" + targetUser + "'.");
                }
            }

        } catch (ConnectException e) {
            System.err.println("Error: Could not connect to server at " + host + ":" + port);
        } catch (IOException e) {
            System.err.println("Error communicating with server: " + e.getMessage());
        }
    }

    /**
     * Receives files from the server (from the current user's directory).
     */
    private static void receiveFiles(String host, int port, String username, List<String> filenames) {
        try (
            Socket socket = new Socket(host, port);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream())
        ) {
            out.writeUTF("RECEIVE");
            out.writeUTF(username);
            out.writeInt(filenames.size());

            for (String filename : filenames) {
                out.writeUTF(filename);

                String response = in.readUTF();
                if (response.startsWith("ERROR")) {
                    System.err.println("Error receiving '" + filename + "': " + response);
                    continue;
                }

                // Read file size
                long fileSize = in.readLong();

                // Check if file already exists locally
                File destFile = new File(filename);
                if (destFile.exists()) {
                    System.err.println("Error: File '" + filename + "' already exists locally. Skipping.");
                    // Drain the stream
                    in.skipNBytes(fileSize);
                    continue;
                }

                // Write file
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
                }

                System.out.println("File '" + filename + "' received successfully.");
            }

        } catch (ConnectException e) {
            System.err.println("Error: Could not connect to server at " + host + ":" + port);
        } catch (IOException e) {
            System.err.println("Error communicating with server: " + e.getMessage());
        }
    }

    // ─── Argument parsing helpers ───────────────────────────────────────────────

    /**
     * Parses CLI args into a map: flag -> list of values.
     * Single-value flags: -s, -u, -t, -p
     * Multi-value flags: -e, -r
     */
    private static Map<String, List<String>> parseArgs(String[] args) {
        Map<String, List<String>> params = new LinkedHashMap<>();
        String currentFlag = null;

        for (String arg : args) {
            if (arg.startsWith("-")) {
                currentFlag = arg;
                params.put(currentFlag, new ArrayList<>());
            } else {
                if (currentFlag == null) {
                    System.err.println("Error: Unexpected argument: " + arg);
                    return null;
                }
                params.get(currentFlag).add(arg);
            }
        }

        return params;
    }

    /**
     * Returns the first value of a flag, or null.
     */
    private static String getParam(Map<String, List<String>> params, String flag) {
        List<String> values = params.get(flag);
        if (values == null || values.isEmpty()) return null;
        return values.get(0);
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Send files:    mySaude -s address:port -u username -e file1 [file2 ...] -t targetUser");
        System.out.println("  Receive files: mySaude -s address:port -u username -r file1 [file2 ...]");
    }
}
