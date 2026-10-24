import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronFlare() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("SAFFRON_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronFlareSafeSink()).logSaffronFlare(data);
    }
}

class CWE117_P06_V2_SaffronFlareSafeSink {
    public void logSaffronFlare(String data) {
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
