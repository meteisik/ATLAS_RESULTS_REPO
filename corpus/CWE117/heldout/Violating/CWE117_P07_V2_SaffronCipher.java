import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronCipher() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = (new CWE117_P07_V2_SaffronCipherSource()).readSaffronCipher();
        } else {
            data = null;
        }
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronCipherSource {
    public String readSaffronCipher() {
        String data;
        data = System.getenv("SAFFRON_CIPHER_USER");
        return data;
    }
}
