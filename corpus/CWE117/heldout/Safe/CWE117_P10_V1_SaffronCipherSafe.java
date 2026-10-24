import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronCipherSafe {

    public static String data;

    public void handleSaffronCipher() {
        data = System.getenv("SAFFRON_CIPHER_USER");
        (new CWE117_P10_V1_SaffronCipherSafeSink()).logSaffronCipher();
    }
}

class CWE117_P10_V1_SaffronCipherSafeSink {
    public void logSaffronCipher() {
        String data = CWE117_P10_V1_SaffronCipherSafe.data;
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
