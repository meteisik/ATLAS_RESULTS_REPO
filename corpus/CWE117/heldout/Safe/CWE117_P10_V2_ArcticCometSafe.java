import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleArcticComet() {
        if (IO.staticTrue) {
            data = System.getenv("ARCTIC_COMET_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticCometSafeSink()).logArcticComet();
    }
}

class CWE117_P10_V2_ArcticCometSafeSink {
    public void logArcticComet() {
        String data = CWE117_P10_V2_ArcticCometSafe.data;
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
