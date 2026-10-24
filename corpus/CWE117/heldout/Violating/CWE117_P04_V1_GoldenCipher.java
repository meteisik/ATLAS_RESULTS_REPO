import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenCipher {

    private String readGoldenCipher() {
        String data;
        data = System.getenv("GOLDEN_CIPHER_USER");
        return data;
    }

    public void handleGoldenCipher() {
        String data = readGoldenCipher();
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + data);
    }
}
