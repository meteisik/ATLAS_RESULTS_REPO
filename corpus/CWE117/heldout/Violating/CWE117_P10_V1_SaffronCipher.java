import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronCipher {

    public static String data;

    public void handleSaffronCipher() {
        data = System.getenv("SAFFRON_CIPHER_USER");
        (new CWE117_P10_V1_SaffronCipherSink()).logSaffronCipher();
    }
}

class CWE117_P10_V1_SaffronCipherSink {
    public void logSaffronCipher() {
        String data = CWE117_P10_V1_SaffronCipher.data;
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + data);
    }
}
