import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronGlint() {
        String data;
        if (IO.staticFive == 5) {
            data = (new CWE117_P07_V2_SaffronGlintSafeSource()).readSaffronGlint();
        } else {
            data = null;
        }
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronGlintSafeSource {
    public String readSaffronGlint() {
        String data;
        data = System.getenv("SAFFRON_GLINT_USER");
        return data;
    }
}
