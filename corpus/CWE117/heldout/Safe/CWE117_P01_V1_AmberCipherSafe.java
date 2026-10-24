import java.util.logging.Logger;

public class CWE117_P01_V1_AmberCipherSafe {

    public void handleAmberCipher() {
        String data;
        data = System.getenv("AMBER_CIPHER_USER");
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
