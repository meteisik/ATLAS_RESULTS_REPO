import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronMantis() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SAFFRON_MANTIS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronMantisSafeSink()).logSaffronMantis(data);
    }
}

class CWE117_P06_V2_SaffronMantisSafeSink {
    public void logSaffronMantis(String data) {
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
