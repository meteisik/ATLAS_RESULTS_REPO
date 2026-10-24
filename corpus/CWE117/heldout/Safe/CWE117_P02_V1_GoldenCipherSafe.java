import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenCipherSafe {

    public void handleGoldenCipher() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_CIPHER_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
            goldenCipherLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
