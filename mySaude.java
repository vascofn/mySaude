import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.*;

//Alterei umas cenas para que dê para criptografar offline (-c e -d) e corrigi o protocolo SEND para bater com o do Server

// classe que age como cliente do servidor mySaude
public class mySaude {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        Map<String, List<String>> params = parseArgs(args);
        if (params == null) {
            printUsage();
            System.exit(1);
        }

        // operação principal (neste trabalho assume-se 1 por execução)
        boolean isEncrypt = params.containsKey("-c");
        boolean isDecrypt = params.containsKey("-d");
        boolean isSend = params.containsKey("-e");
        boolean isReceive = params.containsKey("-r");
        boolean isSign = params.containsKey("-a");
        boolean isValidate = params.containsKey("-v");
        boolean isSignandisSend = params.containsKey("-ae");
        boolean isValidateandisReceive = params.containsKey("-rv");
        boolean isSecureEnvelope = params.containsKey("-ace");
        boolean isEncryptAndSend = params.containsKey("-ce");
        boolean isReceiveAndDecrypt = params.containsKey("-rd");
        boolean isReceiveDecryptVerify = params.containsKey("-rdv");


        String username = getParam(params, "-u");
        if (username == null) {
            System.err.println("Error: -u (username) é obrigatório.");
            printUsage();
            System.exit(1);
        }
        // assinaturas digitais
        if (isSign || isValidate){
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -c/-d.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            // assina o ficheiro
            if (isSign){
                signFiles(username, passChars, params.get("-a"));
                return;
            }
        // valida o ficheiro assinado
        if(isValidate){
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (username de quem assinou) é obrigatório com -v.");
                System.exit(1);
            }
            validateFiles(username, passChars, targetUser, params.get("-v"));
            return;
        }
        }
        // sing and send 
        if (isSignandisSend){
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -c/-d.");
                System.exit(1);
            }
            String serverAddress = getParam(params, "-s");
            if (serverAddress == null) {
                System.err.println("Error: -s (address:port) é obrigatório com -e/-r.");
                printUsage();
                System.exit(1);
            }
            String[] serverParts = serverAddress.split(":");
            if (serverParts.length != 2) {
                System.err.println("Error: Server address must be in format address:port");
                System.exit(1);
            }
            String host = serverParts[0]; 
            int port;
            try {
                port = Integer.parseInt(serverParts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid port number.");
                System.exit(1);
                return;
            }
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (username de quem assinou) é obrigatório com -v.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            List<String> files = signFiles(username, passChars, params.get("-ae"));
            sendFiles(host,port,username,targetUser, files);
            return;
        }
        // validar e receber 
        if (isValidateandisReceive) {
        String password = getParam(params, "-p");
        if (password == null) {
            System.err.println("Error: -p (password da keystore) é obrigatório com -rv.");
            System.exit(1);
        }
        String serverAddress = getParam(params, "-s");
        if (serverAddress == null) {
            System.err.println("Error: -s (address:port) é obrigatório com -rv.");
            System.exit(1);
        }
        String[] serverParts = serverAddress.split(":");
        if (serverParts.length != 2) {
            System.err.println("Error: Server address must be in format address:port");
            System.exit(1);
        }
        String host = serverParts[0];
        int port;
        try {
            port = Integer.parseInt(serverParts[1]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid port number.");
            System.exit(1);
            return;
        }
        String targetUser = getParam(params, "-t");
        if (targetUser == null) {
            System.err.println("Error: -t (username de quem assinou) é obrigatório com -rv.");
            System.exit(1);
        }
        char[] passChars = password.toCharArray();
        List<String> files = params.get("-rv"); 

        // Para cada ficheiro, pede também a assinatura ao servidor
        List<String> ficheirosParaReceber = new ArrayList<>();
        for (String f : files) {
            ficheirosParaReceber.add(f);                              // ficheiro original
            ficheirosParaReceber.add(f + ".assinatura." + targetUser); // assinatura
        }

        // Recebe ambos do servidor
        receiveFiles(host, port, username, ficheirosParaReceber);

        // Valida as assinaturas localmente
        validateFiles(username, passChars, targetUser, files);
        return;
    }


        // -ace: assinar + cifrar + enviar (envelope seguro)
        if (isSecureEnvelope) {
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -ace.");
                System.exit(1);
            }
            String serverAddress = getParam(params, "-s");
            if (serverAddress == null) {
                System.err.println("Error: -s (address:port) é obrigatório com -ace.");
                System.exit(1);
            }
            String[] serverParts = serverAddress.split(":");
            if (serverParts.length != 2) {
                System.err.println("Error: Server address must be in format address:port");
                System.exit(1);
            }
            String host = serverParts[0];
            int port;
            try {
                port = Integer.parseInt(serverParts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid port number.");
                System.exit(1);
                return;
            }
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (destinatário) é obrigatório com -ace.");
                System.exit(1);
            }
            List<String> files = params.get("-ace");
            if (files == null || files.isEmpty()) {
                System.err.println("Error: tens de indicar ficheiros com -ace.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            secureEnvelopeSend(host, port, username, passChars, targetUser, files);
            return;
        }

        // -rdv: receber + decifrar + verificar assinatura
        if (isReceiveDecryptVerify) {
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -rdv.");
                System.exit(1);
            }
            String serverAddress = getParam(params, "-s");
            if (serverAddress == null) {
                System.err.println("Error: -s (address:port) é obrigatório com -rdv.");
                System.exit(1);
            }
            String[] serverParts = serverAddress.split(":");
            if (serverParts.length != 2) {
                System.err.println("Error: Server address must be in format address:port");
                System.exit(1);
            }
            String host = serverParts[0];
            int port;
            try {
                port = Integer.parseInt(serverParts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid port number.");
                System.exit(1);
                return;
            }
            String signer = getParam(params, "-t");
            if (signer == null) {
                System.err.println("Error: -t (username de quem assinou) é obrigatório com -rdv.");
                System.exit(1);
            }
            List<String> files = params.get("-rdv");
            if (files == null || files.isEmpty()) {
                System.err.println("Error: tens de indicar ficheiros com -rdv.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            secureEnvelopeReceive(host, port, username, passChars, signer, files);
            return;
        }

        // -ce: cifrar + enviar
        if (isEncryptAndSend) {
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -ce.");
                System.exit(1);
            }
            String serverAddressCE = getParam(params, "-s");
            if (serverAddressCE == null) {
                System.err.println("Error: -s (address:port) é obrigatório com -ce.");
                System.exit(1);
            }
            String[] serverPartsCE = serverAddressCE.split(":");
            if (serverPartsCE.length != 2) {
                System.err.println("Error: Server address must be in format address:port");
                System.exit(1);
            }
            String hostCE = serverPartsCE[0];
            int portCE ;
            try {
                portCE = Integer.parseInt(serverPartsCE[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid port number.");
                System.exit(1);
                return;
            }
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (destinatário) é obrigatório com -ce.");
                System.exit(1);
            }
            List<String> files = params.get("-ce");
            if (files == null || files.isEmpty()) {
                System.err.println("Error: tens de indicar ficheiros com -ce.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            encryptAndSend(hostCE, portCE, username, passChars, targetUser, files);
            return;
        }
        
        // -rd: receber + decifrar
        if (isReceiveAndDecrypt) {
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -rd.");
                System.exit(1);
            }
            String serverAddressRD = getParam(params, "-s");
            if (serverAddressRD == null) {
                System.err.println("Error: -s (address:port) é obrigatório com -rd.");
                System.exit(1);
            }
            String[] serverPartsRD = serverAddressRD.split(":");
            if (serverPartsRD.length != 2) {
                System.err.println("Error: Server address must be in format address:port");
                System.exit(1);
            }
            String hostRD = serverPartsRD[0];
            int portRD;
            try {
                portRD = Integer.parseInt(serverPartsRD[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid port number.");
                System.exit(1);
                return;
            }
            List<String> files = params.get("-rd");
            if (files == null || files.isEmpty()) {
                System.err.println("Error: tens de indicar ficheiros com -rd.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();
            receiveAndDecrypt(hostRD, portRD, username, passChars, files);
            return;
        }

        // ---- CRIPTO (offline; NÃO usa servidor) ----
        if (isEncrypt || isDecrypt) {
            String password = getParam(params, "-p");
            if (password == null) {
                System.err.println("Error: -p (password da keystore) é obrigatório com -c/-d.");
                System.exit(1);
            }
            char[] passChars = password.toCharArray();

            if (isEncrypt) {
                String targetUser = getParam(params, "-t");
                if (targetUser == null) {
                    System.err.println("Error: -t (destinatário) é obrigatório com -c.");
                    System.exit(1);
                }
                List<String> files = params.get("-c");
                if (files == null || files.isEmpty()) {
                    System.err.println("Error: tens de indicar ficheiros com -c.");
                    System.exit(1);
                }
                encryptFilesOffline(username, passChars, targetUser, files);
                return;
            }

            if (isDecrypt) {
                List<String> files = params.get("-d");
                if (files == null || files.isEmpty()) {
                    System.err.println("Error: tens de indicar ficheiros com -d.");
                    System.exit(1);
                }
                decryptFilesOffline(username, passChars, files);
                return;
            }
        }

        // ---- REDE (usa servidor) ----
        if (!(isSend || isReceive)) {
            System.err.println("Error: tens de indicar uma opção principal (-e/-r/-c/-d).");
            printUsage();
            System.exit(1);
        }

        String serverAddress = getParam(params, "-s");
        if (serverAddress == null) {
            System.err.println("Error: -s (address:port) é obrigatório com -e/-r.");
            printUsage();
            System.exit(1);
        }

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

        if (isSend) {
            List<String> files = params.get("-e");
            String targetUser = getParam(params, "-t");
            if (targetUser == null) {
                System.err.println("Error: -t (target username) is required with -e");
                System.exit(1);
            }
            sendFiles(host, port, username, targetUser, files);

        } else if (isReceive) {
            List<String> files = params.get("-r");
            receiveFiles(host, port, username, files);
        }
    }

    // ---------------- CRIPTO: -c / -d (offline) ----------------

    private static void encryptFilesOffline(String username, char[] ksPass, String targetUser, List<String> filenames) {
        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeyStore(username, ksPass);
        } catch (Exception e) {
            System.err.println("Erro a carregar keystore do utilizador '" + username + "': " + e.getMessage());
            return;
        }

        Certificate targetCert;
        try {
            targetCert = ks.getCertificate(targetUser);
        } catch (Exception e) {
            System.err.println("Erro: certificado do destinatário '" + targetUser + "' não existe na tua keystore: " + e.getMessage());
            return;
        }

        for (String fn : filenames) {
            try {
                Path in = Paths.get(fn);
                Path outCipher = HybridCrypto.cipherFileName(in);
                Path outKey = HybridCrypto.keyFileName(in, targetUser);

                HybridCrypto.encryptFile(in, targetCert, outCipher, outKey);
                System.out.println("OK: cifrado '" + fn + "' -> '" + outCipher.getFileName() + "', '" + outKey.getFileName() + "'");
            } catch (Exception e) {
                System.err.println("ERRO a cifrar '" + fn + "': " + e.getMessage());
                // continua para o próximo ficheiro
            }
        }
    }

    private static void decryptFilesOffline(String username, char[] ksPass, List<String> cipherFiles) {
        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeyStore(username, ksPass);
        } catch (Exception e) {
            System.err.println("Erro a carregar keystore do utilizador '" + username + "': " + e.getMessage());
            return;
        }

        PrivateKey mySk;
        try {
            mySk = KeyStoreUtil.getPrivateKey(ks, username, ksPass);
        } catch (Exception e) {
            System.err.println("Erro a obter chave privada do utilizador '" + username + "': " + e.getMessage());
            return;
        }

        for (String fn : cipherFiles) {
            try {
                Path cipher = Paths.get(fn);
                Path keyFile = HybridCrypto.expectedKeyFileForDecrypt(cipher, username);

                if (!Files.exists(keyFile)) {
                    System.err.println("ERRO: chave para decifrar em falta: '" + keyFile.getFileName() + "'");
                    continue;
                }

                Path outPlain = HybridCrypto.suggestedPlainOutput(cipher);
                HybridCrypto.decryptFile(cipher, keyFile, mySk, outPlain);

                System.out.println("OK: decifrado '" + fn + "' -> '" + outPlain.getFileName() + "'");
            } catch (Exception e) {
                System.err.println("ERRO a decifrar '" + fn + "': " + e.getMessage());
            }
        }
    }

    // ---------------- REDE: -e / -r ----------------

    private static void sendFiles(String host, int port, String username,String targetUser, List<String> filenames) {
        List<File> validFiles = new ArrayList<>();
        for (String filename : filenames) {
            File f = new File(filename);
            if (!f.exists() || !f.isFile()) {
                System.err.println("Error: File '" + filename + "' does not exist on client.");
                continue;
            }
            validFiles.add(f);
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
            out.writeUTF("SEND");
            out.writeUTF(targetUser);
            out.writeInt(validFiles.size());
            out.flush();
            byte[] buffer = new byte[1024];
            for (File file : validFiles) {
                out.writeUTF(file.getName());
                out.flush();
                // o servidor responde aqui 
                String precheck = in.readUTF();
                if (precheck.startsWith("ERROR")) {
                    System.err.println("Error sending '" + file.getName() + "': " + precheck);
                    // para manter o protocolo do servidor, envia tamanho 0 e segue
                    out.writeLong(0L);
                    out.flush();
                    continue;
                }
                out.writeLong(file.length());
                try (FileInputStream fis = new FileInputStream(file)) {
                    int read;
                    while ((read = fis.read(buffer)) != -1) {
                        out.write(buffer, 0, read);
                    }
                }
                out.flush();
                // ack final do servidor
                String response = in.readUTF();
                if (response.startsWith("ERROR")) {
                    System.err.println("Error sending '" + file.getName() + "': " + response);
                } else {
                    System.out.println("File '" + file.getName() + "' sent successfully to user '" + targetUser + "'.");
                }
            }
        } catch (ConnectException e) {
            System.err.println("Error: Could not connect to server at " + host + ":" + port);
        } catch (IOException e) {
            System.err.println("Error communicating with server: " + e.getMessage());
        }
    }


    /**
 * -ace: para cada ficheiro:
 *   1. Assina → ficheiro.assinatura.username
 *   2. Cifra  → ficheiro.envelope  +  ficheiro.chave.targetUser
 *   3. Envia os 3 ficheiros para o servidor (pasta do targetUser)
 */
private static void secureEnvelopeSend(String host, int port, String username,
                                        char[] passChars, String targetUser,
                                        List<String> filenames) {
    // Carregar keystore do remetente
    KeyStore ks;
    try {
        ks = KeyStoreUtil.loadKeyStore(username, passChars);
    } catch (Exception e) {
        System.err.println("Erro a carregar keystore de '" + username + "': " + e.getMessage());
        return;
    }
 
    // Chave privada do remetente (para assinar)
    java.security.PrivateKey pk;
    try {
        pk = KeyStoreUtil.getPrivateKey(ks, username, passChars);
    } catch (Exception e) {
        System.err.println("Erro a obter chave privada de '" + username + "': " + e.getMessage());
        return;
    }
 
    // Certificado do destinatário (para cifrar a chave AES)
    java.security.cert.Certificate targetCert;
    try {
        targetCert = ks.getCertificate(targetUser);
        if (targetCert == null) throw new Exception("Certificado não encontrado.");
    } catch (Exception e) {
        System.err.println("Erro: certificado de '" + targetUser + "' não existe na tua keystore. Importa-o com keytool.");
        return;
    }
 
    // Processar cada ficheiro
    List<String> filesToSend = new ArrayList<>();
 
    for (String fn : filenames) {
        java.nio.file.Path input = java.nio.file.Paths.get(fn);
 
        if (!java.nio.file.Files.exists(input)) {
            System.err.println("ERRO: ficheiro '" + fn + "' não existe. A saltar.");
            continue;
        }
 
        String baseName = input.getFileName().toString();
        String sigFile    = fn + ".assinatura." + username;
        String envelopeFile = fn + ".envelope";
        String keyFile    = fn + ".chave." + targetUser;
 
        try {
            // 1. Assinar o ficheiro original
            byte[] assinatura = DigitalSignatureUtil.signFile(fn, pk);
            java.nio.file.Files.write(java.nio.file.Path.of(sigFile), assinatura);
            System.out.println("OK: assinado '" + fn + "' -> '" + sigFile + "'");
 
            // 2. Cifrar o ficheiro original (cria .envelope e .chave.targetUser)
            java.nio.file.Path outEnvelope = java.nio.file.Paths.get(envelopeFile);
            java.nio.file.Path outKey      = java.nio.file.Paths.get(keyFile);
            HybridCrypto.encryptFile(input, targetCert, outEnvelope, outKey);
            System.out.println("OK: cifrado '" + fn + "' -> '" + envelopeFile + "', '" + keyFile + "'");
 
            // 3. Adicionar os 3 ficheiros à lista de envio
            filesToSend.add(envelopeFile);
            filesToSend.add(sigFile);
            filesToSend.add(keyFile);
 
        } catch (Exception e) {
            System.err.println("ERRO a processar '" + fn + "': " + e.getMessage());
            // Limpar ficheiros parcialmente criados
            new java.io.File(sigFile).delete();
            new java.io.File(envelopeFile).delete();
            new java.io.File(keyFile).delete();
        }
    }
 
    if (filesToSend.isEmpty()) {
        System.out.println("Nenhum ficheiro para enviar.");
        return;
    }
 
    // 3. Enviar todos para o servidor
    sendFiles(host, port, username, targetUser, filesToSend);
}
 
/**
 * -rdv: para cada ficheiro:
 *   1. Recebe do servidor: ficheiro.envelope, ficheiro.assinatura.signer, ficheiro.chave.username
 *   2. Decifra o .envelope → ficheiro.decifrado
 *   3. Valida a assinatura
 */
private static void secureEnvelopeReceive(String host, int port, String username,
                                           char[] passChars, String signer,
                                           List<String> filenames) {
    // Carregar keystore do destinatário
    KeyStore ks;
    try {
        ks = KeyStoreUtil.loadKeyStore(username, passChars);
    } catch (Exception e) {
        System.err.println("Erro a carregar keystore de '" + username + "': " + e.getMessage());
        return;
    }
 
    // Chave privada do destinatário (para decifrar)
    java.security.PrivateKey mySk;
    try {
        mySk = KeyStoreUtil.getPrivateKey(ks, username, passChars);
    } catch (Exception e) {
        System.err.println("Erro a obter chave privada de '" + username + "': " + e.getMessage());
        return;
    }
 
    // Certificado de quem assinou (para verificar)
    java.security.cert.Certificate signerCert;
    try {
        signerCert = ks.getCertificate(signer);
        if (signerCert == null) throw new Exception("Certificado não encontrado.");
    } catch (Exception e) {
        System.err.println("Erro: certificado de '" + signer + "' não existe na tua keystore. Importa-o com keytool.");
        return;
    }
 
    for (String fn : filenames) {
        String envelopeFile = fn + ".envelope";
        String sigFile      = fn + ".assinatura." + signer;
        String keyFile      = fn + ".chave." + username;
 
        // 1. Receber os 3 ficheiros do servidor
        List<String> toReceive = new ArrayList<>();
        toReceive.add(envelopeFile);
        toReceive.add(sigFile);
        toReceive.add(keyFile);
        receiveFiles(host, port, username, toReceive);
 
        // Verificar se foram todos recebidos
        if (!new java.io.File(envelopeFile).exists()) {
            System.err.println("ERRO: não foi possível receber '" + envelopeFile + "'. A saltar.");
            continue;
        }
        if (!new java.io.File(keyFile).exists()) {
            System.err.println("ERRO: não foi possível receber '" + keyFile + "'. A saltar.");
            continue;
        }
        if (!new java.io.File(sigFile).exists()) {
            System.err.println("ERRO: não foi possível receber '" + sigFile + "'. A saltar.");
            continue;
        }
 
        // 2. Decifrar o envelope
        try {
            java.nio.file.Path cipher  = java.nio.file.Paths.get(envelopeFile);
            java.nio.file.Path keyPath = java.nio.file.Paths.get(keyFile);
            java.nio.file.Path outPlain = java.nio.file.Paths.get(fn + ".decifrado");
            HybridCrypto.decryptFile(cipher, keyPath, mySk, outPlain);
            System.out.println("OK: decifrado '" + envelopeFile + "' -> '" + fn + ".decifrado'");
        } catch (Exception e) {
            System.err.println("ERRO a decifrar '" + envelopeFile + "': " + e.getMessage());
            continue;
        }
 
        // 3. Verificar assinatura (sobre o ficheiro ORIGINAL, i.e., o decifrado)
        try {
            java.io.File decifrado = new java.io.File(fn + ".decifrado");
            byte[] sigBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(sigFile));
            boolean valida = DigitalSignatureUtil.verifyFileSignature(decifrado, sigBytes, signerCert);
            if (valida) {
                System.out.println("OK: assinatura de '" + fn + "' por '" + signer + "' é VÁLIDA.");
            } else {
                System.out.println("INVÁLIDA: assinatura de '" + fn + "' por '" + signer + "' é INVÁLIDA.");
            }
        } catch (Exception e) {
            System.err.println("ERRO a verificar assinatura de '" + fn + "': " + e.getMessage());
        }
    }
}


    private static void receiveFiles(String host, int port, String username, List<String> filenames) {
        for (String filename : filenames) {
            File destFile = new File(filename);
            if (destFile.exists()) {
                System.err.println("Error: File '" + filename + "' already exists locally. Skipping.");
                continue;
            }
            try (
                Socket socket = new Socket(host, port);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())
            ) {
                out.writeUTF("RECEIVE");
                out.writeUTF(username);
                out.writeInt(1);
                out.writeUTF(filename);
                out.flush();

                String response = in.readUTF();
                if (response.startsWith("ERROR")) {
                    System.err.println("Error receiving '" + filename + "': " + response);
                    continue;
                }

                long fileSize = in.readLong();

                byte[] buffer = new byte[1024];
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
            } catch (ConnectException e) {
                System.err.println("Error: Could not connect to server at " + host + ":" + port);
            } catch (IOException e) {
                System.err.println("Error communicating with server: " + e.getMessage());
            }
        }
    }
        // ---------------- ASSINATURA DIGITAL: -a ----------------

        private static List<String> signFiles(String username, char[] passChars, List<String> files) {
            List<String> lista_files = new ArrayList<>();
            if (files == null || files.isEmpty()) {
                System.err.println("Error: -a não deste nenhum file.");
                System.exit(1);
            }
            try {
                KeyStore ks = KeyStoreUtil.loadKeyStore(username, passChars);
                PrivateKey pk = KeyStoreUtil.getPrivateKey(ks, username, passChars);
                for (String f : files) {
                    File ficheiro = new File(f);
                    if (!ficheiro.exists()) {
                        System.err.println("ERRO: ficheiro '" + f + "' não existe. A saltar.");
                        continue;
                    }
                    byte[] assinatura = DigitalSignatureUtil.signFile(f, pk);
                    String ficheiroAssinado = f + ".assinatura." + username;
                    Files.write(Path.of(ficheiroAssinado), assinatura);
                    lista_files.add(f);
                    lista_files.add(ficheiroAssinado);
                    System.out.println("OK: ficheiro '" + f + "' assinado -> '" + ficheiroAssinado + "'");
                }
            } catch (Exception e) {
                System.err.println("Erro ao assinar ficheiro: " + e.getMessage());
                System.exit(1);
            }
            return lista_files;

        }

        // ---------------- VALIDAR ASSINATURA: -v ----------------

        private static void validateFiles(String username, char[] passChars, String targetUser, List<String> files) {
            if (files == null || files.isEmpty()) {
                System.err.println("Error: -v não deste nenhum ficheiro para verificar a assinatura.");
                System.exit(1);
            }
            try {
                KeyStore ks = KeyStoreUtil.loadKeyStore(username, passChars);
                Certificate cert = ks.getCertificate(targetUser);
                if (cert == null) {
                    System.err.println("ERRO: certificado de '" + targetUser + "' não encontrado na keystore.");
                    System.exit(1);
                }
                for (String f : files) {
                    File ficheiro = new File(f);
                    if (!ficheiro.exists()) {
                        System.err.println("ERRO: ficheiro '" + f + "' não existe.");
                        continue;
                    }
                    String assinaturaPath = f + ".assinatura." + targetUser;
                    File assinaturaFile = new File(assinaturaPath);
                    if (!assinaturaFile.exists()) {
                        System.err.println("ERRO: ficheiro de assinatura '" + assinaturaPath + "' não existe.");
                        continue;
                    }
                    byte[] assinaturaBytes = Files.readAllBytes(assinaturaFile.toPath());
                    boolean valida = DigitalSignatureUtil.verifyFileSignature(ficheiro, assinaturaBytes, cert);
                    if (valida) {
                        System.out.println("OK: assinatura de '" + f + "' por '" + targetUser + "' é VÁLIDA.");
                    } else {
                        System.out.println("INVÁLIDA: assinatura de '" + f + "' por '" + targetUser + "' é INVÁLIDA.");
                    }
                }
            } catch (Exception e) {
                System.err.println("Erro ao verificar assinatura: " + e.getMessage());
                System.exit(1);
            }
        }
    // ─── Argument parsing helpers ───────────────────────────────────────────────

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
     * -ce: para cada ficheiro:
     *   1. Cifra → ficheiro.cifrado + ficheiro.chave.targetUser
     *   2. Envia os 2 ficheiros para o servidor (pasta do targetUser)
     */
    private static void encryptAndSend(String host, int port, String username,
                                        char[] passChars, String targetUser,
                                        List<String> filenames) {
        // Carregar keystore
        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeyStore(username, passChars);
        } catch (Exception e) {
            System.err.println("Erro a carregar keystore de '" + username + "': " + e.getMessage());
            return;
        }
    
        // Certificado do destinatário (para cifrar a chave AES)
        java.security.cert.Certificate targetCert;
        try {
            targetCert = ks.getCertificate(targetUser);
            if (targetCert == null) throw new Exception("Certificado não encontrado.");
        } catch (Exception e) {
            System.err.println("Erro: certificado de '" + targetUser + "' não existe na tua keystore. Importa-o com keytool.");
            return;
        }
    
        List<String> filesToSend = new ArrayList<>();
    
        for (String fn : filenames) {
            java.nio.file.Path input = java.nio.file.Paths.get(fn);
    
            if (!java.nio.file.Files.exists(input)) {
                System.err.println("ERRO: ficheiro '" + fn + "' não existe. A saltar.");
                continue;
            }
    
            String cipherFile = fn + ".cifrado";
            String keyFile    = fn + ".chave." + targetUser;
    
            try {
                // Cifrar
                java.nio.file.Path outCipher = java.nio.file.Paths.get(cipherFile);
                java.nio.file.Path outKey    = java.nio.file.Paths.get(keyFile);
                HybridCrypto.encryptFile(input, targetCert, outCipher, outKey);
                System.out.println("OK: cifrado '" + fn + "' -> '" + cipherFile + "', '" + keyFile + "'");
    
                // Adicionar à lista de envio
                filesToSend.add(cipherFile);
                filesToSend.add(keyFile);
    
            } catch (Exception e) {
                System.err.println("ERRO a cifrar '" + fn + "': " + e.getMessage());
                new java.io.File(cipherFile).delete();
                new java.io.File(keyFile).delete();
            }
        }
    
        if (filesToSend.isEmpty()) {
            System.out.println("Nenhum ficheiro para enviar.");
            return;
        }
    
        // Enviar para o servidor
        sendFiles(host, port, username, targetUser, filesToSend);
    }
    
    /**
     * -rd: para cada ficheiro:
     *   1. Recebe do servidor: ficheiro.cifrado + ficheiro.chave.username
     *   2. Decifra o .cifrado → ficheiro.decifrado
     */
    private static void receiveAndDecrypt(String host, int port, String username,
                                        char[] passChars, List<String> filenames) {
        // Carregar keystore
        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeyStore(username, passChars);
        } catch (Exception e) {
            System.err.println("Erro a carregar keystore de '" + username + "': " + e.getMessage());
            return;
        }
    
        // Chave privada (para decifrar)
        java.security.PrivateKey mySk;
        try {
            mySk = KeyStoreUtil.getPrivateKey(ks, username, passChars);
        } catch (Exception e) {
            System.err.println("Erro a obter chave privada de '" + username + "': " + e.getMessage());
            return;
        }
    
        for (String fn : filenames) {
            String cipherFile = fn + ".cifrado";
            String keyFile    = fn + ".chave." + username;
    
            // 1. Receber os 2 ficheiros do servidor
            List<String> toReceive = new ArrayList<>();
            toReceive.add(cipherFile);
            toReceive.add(keyFile);
            receiveFiles(host, port, username, toReceive);
    
            // Verificar se foram recebidos
            if (!new java.io.File(cipherFile).exists()) {
                System.err.println("ERRO: não foi possível receber '" + cipherFile + "'. A saltar.");
                continue;
            }
            if (!new java.io.File(keyFile).exists()) {
                System.err.println("ERRO: não foi possível receber '" + keyFile + "'. A saltar.");
                continue;
            }
    
            // 2. Decifrar
            try {
                java.nio.file.Path cipher   = java.nio.file.Paths.get(cipherFile);
                java.nio.file.Path keyPath  = java.nio.file.Paths.get(keyFile);
                java.nio.file.Path outPlain = java.nio.file.Paths.get(fn + ".decifrado");
                HybridCrypto.decryptFile(cipher, keyPath, mySk, outPlain);
                System.out.println("OK: decifrado '" + cipherFile + "' -> '" + fn + ".decifrado'");
            } catch (Exception e) {
                System.err.println("ERRO a decifrar '" + cipherFile + "': " + e.getMessage());
            }
        }
    }
    

    private static String getParam(Map<String, List<String>> params, String flag) {
        List<String> values = params.get(flag);
        if (values == null || values.isEmpty()) return null;
        return values.get(0);
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Cifrar:         mySaude -u username -p password -c f1 [f2 ...] -t destinatario");
        System.out.println("  Decifrar:     mySaude -u username -p password -d f1.cifrado [f2.cifrado ...]");
        System.out.println("  Enviar:        mySaude -s address:port -u username -e file1 [file2 ...] -t targetUser");
        System.out.println("  Receber:     mySaude -s address:port -u username -r file1 [file2 ...]");
        System.out.println("  Assinarr:     mySaude -u username -p password_utilizador -a [ficheiros]");
        System.out.println("  Validar:       mySaude -u username -p password_utilizador -v ficheiro -destinatario");

    }
}
