import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Utilitário para carregar keystores e obter chaves/certificados.
 *
 * Requisitos do enunciado:
 * - keystore do utilizador chama-se "keystore.<username>"
 * - o alias (string que identifica o user) coincide com o username
 * - a keystore deve conter os certificados necessários; se não existir, dá erro
 */
public final class KeyStoreUtil {

    private KeyStoreUtil() {}

    public static String keystoreFileName(String username) {
        return "keystore." + username;
    }

    public static KeyStore loadKeyStore(String username, char[] password) throws Exception {
        String ksPath = keystoreFileName(username);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType()); 
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, password);
        } catch (IOException e) {
            throw new IOException("Erro a abrir a keystore '" + ksPath + "'. Verifica o ficheiro e a password.", e);
        }
        return ks;
    }

    public static PrivateKey getPrivateKey(KeyStore ks, String alias, char[] password) throws Exception {
        Key key = ks.getKey(alias, password);
        if (key == null) {
            throw new IllegalStateException("Chave privada em falta na keystore para o alias '" + alias + "'.");
        }
        if (!(key instanceof PrivateKey)) {
            throw new IllegalStateException("O alias '" + alias + "' não corresponde a uma chave privada.");
        }
        return (PrivateKey) key;
    }

    public static X509Certificate getCertificate(KeyStore ks, String alias) {
        Certificate cert;
        try {
            cert = ks.getCertificate(alias);
        } catch (Exception e) {
            throw new IllegalStateException("Erro a obter certificado para o alias '" + alias + "': " + e.getMessage(), e);
        }
        if (cert == null) {
            throw new IllegalStateException(
                "Certificado em falta na keystore para o alias '" + alias + "'. " +
                "Importa-o com keytool (ex.: certificado do destinatário)."
            );
        }
        if (!(cert instanceof X509Certificate)) {
            throw new IllegalStateException("O certificado do alias '" + alias + "' não é X509.");
        }
        return (X509Certificate) cert;
    }
}
