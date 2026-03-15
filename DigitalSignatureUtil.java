import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.nio.file.Files;

// asinturas digitais
public class DigitalSignatureUtil {
    private static final String SIGNATURE_ALGO = "SHA256withRSA"; //usado na teorica



    //assina a assinatura digital (comandos e sequência todos nas teóricas)
    public static byte[] signFile(String file, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGO);
        signature.initSign(privateKey); //inicializar o objecto para que possa ser criada uma assinatura
        try (InputStream in = new FileInputStream(file)) { 
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) { //inves de ler tudo de uma vez le em chunks para n ocupar tanta memoria 
                signature.update(buffer, 0, read); //adicionar dados que eventualmente serão verificados ou assinados
            }
        }
        return signature.sign(); //criar a assinatura (automaticamente o objecto é re-iniciado para que possa criar uma nova assinatura)

    }

    //verifica assinatura( usa basicamente a mesma logica q o de cima)
    public static boolean verifyFileSignature(File file, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGO);
        signature.initVerify(publicKey);
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                signature.update(buffer, 0, read);
            }
        }
        return signature.verify(signatureBytes);
    }

    // Helper: verifica assinatura usando X509Certificate
    public static boolean verifyFileSignature(File file, byte[] signatureBytes, X509Certificate cert) throws Exception {
        return verifyFileSignature(file, signatureBytes, cert.getPublicKey());
    }
}
