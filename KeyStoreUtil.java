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
        return "keys/keystore." + username;
    }

    public static KeyStore loadKeyStore(String username, char[] password) throws Exception {
        String ksPath = keystoreFileName(username);
        KeyStore ks = KeyStore.getInstance("PKCS12"); 
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


}
