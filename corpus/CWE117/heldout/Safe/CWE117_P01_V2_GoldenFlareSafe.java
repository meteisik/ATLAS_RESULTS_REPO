import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleGoldenFlare() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("GOLDEN_FLARE_USER");
        } else {
            data = null;
        }
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
