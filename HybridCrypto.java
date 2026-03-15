import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

//Esta parte é a cifra hibrida que é usada para cifrar os ficheiros antes de serem enviados
// e depois decifrar os ficheiros recebidos, usando AES para os dados e RSA para a chave AES.

//AI reparou alguns erros que tinha nas classes não me garanto a 100% que esteja bangers

/**
 * Cifra híbrida:
 * - AES-128 para dados
 * - RSA-2048 (OAEP) para cifrar a chave AES
 *
 * Outputs exigidos:
 * - <nome>.cifrado
 * - <nome>.chave.<destinatario>
 */
public final class HybridCrypto {

    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 128; // requisito
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LEN = 12; // recomendado em GCM

    private HybridCrypto() {}

    private static Cipher rsaCipherEncrypt(PublicKey pk) throws Exception {
        // tentar OAEP SHA-256; se não existir no provider, cair para OAEP SHA-1
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, pk);
            return c;
        } catch (Exception ignored) {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, pk);
            return c;
        }
    }

    private static Cipher rsaCipherDecrypt(PrivateKey sk) throws Exception {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, sk);
            return c;
        } catch (Exception ignored) {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, sk);
            return c;
        }
    }

    private static SecretKey generateAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS);
        return kg.generateKey();
    }

    private static byte[] randomIv() {
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static Path cipherFileName(Path input) {
        return input.resolveSibling(input.getFileName().toString() + ".cifrado");
    }

    public static Path keyFileName(Path input, String recipientUsername) {
        return input.resolveSibling(input.getFileName().toString() + ".chave." + recipientUsername);
    }

    private static Path baseFromCipher(Path cipherFile) {
        String name = cipherFile.getFileName().toString();
        if (name.endsWith(".cifrado")) {
            name = name.substring(0, name.length() - ".cifrado".length());
        }
        return cipherFile.resolveSibling(name);
    }

    /**
     * Cifra um ficheiro para um destinatário.
     *
     * @param input ficheiro em claro
     * @param recipientCert certificado (X509) do destinatário (a partir da keystore do remetente)
     * @param outCipher output: <input>.cifrado
     * @param outKey output: <input>.chave.<destinatario>
     */
    public static void encryptFile(Path input, X509Certificate recipientCert, Path outCipher, Path outKey) throws Exception {
        if (!Files.exists(input) || !Files.isRegularFile(input)) {
            throw new IllegalArgumentException("Ficheiro não existe: " + input);
        }

        // 1) AES key + IV
        SecretKey aesKey = generateAesKey();
        byte[] iv = randomIv();

        // 2) Cifrar dados (AES/GCM)
        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // 3) Cifrar (wrap) chave AES com RSA do destinatário
        PublicKey recipientPk = recipientCert.getPublicKey();
        Cipher rsaEnc = rsaCipherEncrypt(recipientPk);
        byte[] wrappedKey = rsaEnc.doFinal(aesKey.getEncoded());

        // 4) Escrever ficheiro .chave.<destinatario> (tamanho + bytes)
        try (DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outKey.toFile())))) {
            dos.writeInt(wrappedKey.length);
            dos.write(wrappedKey);
        }

        // 5) Escrever ficheiro .cifrado com cabeçalho simples: [versao][ivLen][iv][ciphertext...]
        try (FileOutputStream fos = new FileOutputStream(outCipher.toFile());
             BufferedOutputStream bos = new BufferedOutputStream(fos)) {

            bos.write(1); // versao
            bos.write(iv.length); // ivLen
            bos.write(iv);

            try (CipherOutputStream cos = new CipherOutputStream(bos, aesCipher);
                 BufferedInputStream bis = new BufferedInputStream(new FileInputStream(input.toFile()))) {

                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = bis.read(buffer)) != -1) {
                    cos.write(buffer, 0, read);
                }
            }
        }
    }

    /**
     * Decifra um ficheiro .cifrado usando a chave privada do utilizador e o ficheiro .chave.<username>.
     *
     * @param cipherFile ficheiro <base>.cifrado
     * @param wrappedKeyFile ficheiro <base>.chave.<username>
     * @param myPrivateKey chave privada do utilizador (alias == username)
     * @param outPlain output (ficheiro em claro)
     */
    public static void decryptFile(Path cipherFile, Path wrappedKeyFile, PrivateKey myPrivateKey, Path outPlain) throws Exception {
        if (!Files.exists(cipherFile) || !Files.isRegularFile(cipherFile)) {
            throw new IllegalArgumentException("Ficheiro cifrado não existe: " + cipherFile);
        }
        if (!Files.exists(wrappedKeyFile) || !Files.isRegularFile(wrappedKeyFile)) {
            throw new IllegalArgumentException("Ficheiro da chave cifrada não existe: " + wrappedKeyFile);
        }

        // 1) Ler chave AES cifrada (RSA)
        byte[] wrappedKey;
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(wrappedKeyFile.toFile())))) {
            int len = dis.readInt();
            if (len <= 0 || len > 8192) { // sanity
                throw new IllegalStateException("Tamanho inválido da chave cifrada: " + len);
            }
            wrappedKey = dis.readNBytes(len);
            if (wrappedKey.length != len) {
                throw new IllegalStateException("Chave cifrada truncada. Esperado " + len + " bytes.");
            }
        }

        // 2) RSA decrypt => bytes da chave AES
        Cipher rsaDec = rsaCipherDecrypt(myPrivateKey);
        byte[] aesKeyBytes = rsaDec.doFinal(wrappedKey);
        if (aesKeyBytes.length != (AES_KEY_BITS / 8)) {
            // não é fatal, mas indica que algo está errado (keys/algos diferentes)
            throw new IllegalStateException("Tamanho inesperado da chave AES: " + aesKeyBytes.length + " bytes.");
        }
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 3) Ler cabeçalho do .cifrado para obter IV
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(cipherFile.toFile()))) {
            int version = bis.read();
            if (version != 1) {
                throw new IllegalStateException("Versão desconhecida do ficheiro cifrado: " + version);
            }
            int ivLen = bis.read();
            if (ivLen <= 0 || ivLen > 32) {
                throw new IllegalStateException("IV length inválido: " + ivLen);
            }
            byte[] iv = bis.readNBytes(ivLen);
            if (iv.length != ivLen) {
                throw new IllegalStateException("IV truncado. Esperado " + ivLen + " bytes.");
            }

            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

            // 4) Decifrar dados em streaming
            try (CipherInputStream cis = new CipherInputStream(bis, aesCipher);
                 BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outPlain.toFile()))) {

                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = cis.read(buffer)) != -1) {
                    bos.write(buffer, 0, read);
                }
            }
        }
    }

    /**
     * Helpers para nomes exigidos pelo enunciado.
     * Dado "bb.pdf.cifrado" devolve:
     * - base: "bb.pdf"
     * - chave: "bb.pdf.chave.<username>"
     * - output sugerido: "bb.pdf.decifrado"
     */
    public static Path expectedKeyFileForDecrypt(Path cipherFile, String myUsername) {
        Path base = baseFromCipher(cipherFile);
        return base.resolveSibling(base.getFileName().toString() + ".chave." + myUsername);
    }

    public static Path suggestedPlainOutput(Path cipherFile) {
        Path base = baseFromCipher(cipherFile);
        return base.resolveSibling(base.getFileName().toString() + ".decifrado");
    }
}
