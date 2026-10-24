import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleGoldenCipher() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("GOLDEN_CIPHER_USER");
        } else {
            data = null;
        }
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
