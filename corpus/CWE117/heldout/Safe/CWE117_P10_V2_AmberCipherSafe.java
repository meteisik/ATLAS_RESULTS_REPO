import java.util.logging.Logger;

public class CWE117_P10_V2_AmberCipherSafe {

    public static String data;

    public void handleAmberCipher() {
        if (true) {
            data = System.getenv("AMBER_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberCipherSafeSink()).logAmberCipher();
    }
}

class CWE117_P10_V2_AmberCipherSafeSink {
    public void logAmberCipher() {
        String data = CWE117_P10_V2_AmberCipherSafe.data;
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
