import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleArcticKestrel() {
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticKestrelSafeSink()).logArcticKestrel();
    }
}

class CWE117_P10_V2_ArcticKestrelSafeSink {
    public void logArcticKestrel() {
        String data = CWE117_P10_V2_ArcticKestrelSafe.data;
        Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
        arcticKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
