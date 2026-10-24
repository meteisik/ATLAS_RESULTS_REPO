import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrFlare {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleZephyrFlare() {
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrFlareSink()).logZephyrFlare();
    }
}

class CWE117_P10_V2_ZephyrFlareSink {
    public void logZephyrFlare() {
        String data = CWE117_P10_V2_ZephyrFlare.data;
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + data);
    }
}
