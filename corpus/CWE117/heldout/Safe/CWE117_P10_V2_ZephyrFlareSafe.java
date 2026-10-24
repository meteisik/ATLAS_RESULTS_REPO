import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrFlareSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleZephyrFlare() {
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrFlareSafeSink()).logZephyrFlare();
    }
}

class CWE117_P10_V2_ZephyrFlareSafeSink {
    public void logZephyrFlare() {
        String data = CWE117_P10_V2_ZephyrFlareSafe.data;
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
