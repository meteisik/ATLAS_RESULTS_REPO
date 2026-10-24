import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenCipherSafe {

    private String readGoldenCipher() {
        String data;
        data = System.getenv("GOLDEN_CIPHER_USER");
        return data;
    }

    public void handleGoldenCipher() {
        String data = readGoldenCipher();
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
