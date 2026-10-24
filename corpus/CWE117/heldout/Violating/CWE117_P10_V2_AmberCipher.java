import java.util.logging.Logger;

public class CWE117_P10_V2_AmberCipher {

    public static String data;

    public void handleAmberCipher() {
        if (true) {
            data = System.getenv("AMBER_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberCipherSink()).logAmberCipher();
    }
}

class CWE117_P10_V2_AmberCipherSink {
    public void logAmberCipher() {
        String data = CWE117_P10_V2_AmberCipher.data;
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + data);
    }
}
