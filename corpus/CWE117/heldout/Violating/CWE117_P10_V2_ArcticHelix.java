import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleArcticHelix() {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_HELIX_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticHelixSink()).logArcticHelix();
    }
}

class CWE117_P10_V2_ArcticHelixSink {
    public void logArcticHelix() {
        String data = CWE117_P10_V2_ArcticHelix.data;
        Logger arcticHelixLogger = Logger.getLogger("arcticHelix.audit");
        arcticHelixLogger.info("Login attempt for user " + data);
    }
}
