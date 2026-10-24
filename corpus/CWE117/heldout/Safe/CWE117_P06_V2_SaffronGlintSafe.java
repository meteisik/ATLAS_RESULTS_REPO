import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronGlint() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("SAFFRON_GLINT_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronGlintSafeSink()).logSaffronGlint(data);
    }
}

class CWE117_P06_V2_SaffronGlintSafeSink {
    public void logSaffronGlint(String data) {
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
