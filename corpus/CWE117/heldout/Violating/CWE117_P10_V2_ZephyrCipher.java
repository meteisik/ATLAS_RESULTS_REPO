import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrCipher {
    private static int privateFive = 5;

    public static String data;

    public void handleZephyrCipher() {
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrCipherSink()).logZephyrCipher();
    }
}

class CWE117_P10_V2_ZephyrCipherSink {
    public void logZephyrCipher() {
        String data = CWE117_P10_V2_ZephyrCipher.data;
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + data);
    }
}
