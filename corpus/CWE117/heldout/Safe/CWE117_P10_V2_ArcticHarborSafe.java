import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleArcticHarbor() {
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ARCTIC_HARBOR_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticHarborSafeSink()).logArcticHarbor();
    }
}

class CWE117_P10_V2_ArcticHarborSafeSink {
    public void logArcticHarbor() {
        String data = CWE117_P10_V2_ArcticHarborSafe.data;
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
