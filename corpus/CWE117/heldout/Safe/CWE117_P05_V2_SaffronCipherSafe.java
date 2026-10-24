import java.util.logging.Logger;

public class CWE117_P05_V2_SaffronCipherSafe {
    private static int privateFive = 5;

    private String saffronCipherData;

    private void logSaffronCipher() {
        String data = saffronCipherData;
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleSaffronCipher() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SAFFRON_CIPHER_USER");
        } else {
            data = null;
        }
        saffronCipherData = data;
        logSaffronCipher();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
