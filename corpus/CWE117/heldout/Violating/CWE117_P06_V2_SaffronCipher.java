import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronCipher() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("SAFFRON_CIPHER_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronCipherSink()).logSaffronCipher(data);
    }
}

class CWE117_P06_V2_SaffronCipherSink {
    public void logSaffronCipher(String data) {
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + data);
    }
}
