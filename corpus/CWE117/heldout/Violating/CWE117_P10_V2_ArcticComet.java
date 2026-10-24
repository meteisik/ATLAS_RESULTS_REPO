import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticComet {
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
        (new CWE117_P10_V2_ArcticCometSink()).logArcticComet();
    }
}

class CWE117_P10_V2_ArcticCometSink {
    public void logArcticComet() {
        String data = CWE117_P10_V2_ArcticComet.data;
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + data);
    }
}
