import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenCipher {

    private void logGoldenCipher(String data) {
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenCipher() {
        String data;
        data = System.getenv("GOLDEN_CIPHER_USER");
        logGoldenCipher(data);
    }
}
