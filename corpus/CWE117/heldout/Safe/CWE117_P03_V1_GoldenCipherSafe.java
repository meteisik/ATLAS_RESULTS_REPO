import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenCipherSafe {

    private void logGoldenCipher(String data) {
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenCipher() {
        String data;
        data = System.getenv("GOLDEN_CIPHER_USER");
        logGoldenCipher(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
