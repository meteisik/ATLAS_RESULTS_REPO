import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticHarbor {
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
        (new CWE117_P10_V2_ArcticHarborSink()).logArcticHarbor();
    }
}

class CWE117_P10_V2_ArcticHarborSink {
    public void logArcticHarbor() {
        String data = CWE117_P10_V2_ArcticHarbor.data;
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + data);
    }
}
