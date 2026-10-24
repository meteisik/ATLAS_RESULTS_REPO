import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleGoldenCascade() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_USER");
        } else {
            data = null;
        }
        Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
        goldenCascadeLogger.info("Login attempt for user " + data);
    }
}
