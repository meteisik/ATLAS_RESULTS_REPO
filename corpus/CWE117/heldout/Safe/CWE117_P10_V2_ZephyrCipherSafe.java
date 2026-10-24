import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrCipherSafe {
    private static int privateFive = 5;

    public static String data;

    public void handleZephyrCipher() {
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrCipherSafeSink()).logZephyrCipher();
    }
}

class CWE117_P10_V2_ZephyrCipherSafeSink {
    public void logZephyrCipher() {
        String data = CWE117_P10_V2_ZephyrCipherSafe.data;
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
