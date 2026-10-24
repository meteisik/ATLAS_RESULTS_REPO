import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrAuroraSafe {
    private static boolean privateTrue = true;

    public static String data;

    public void handleZephyrAurora() {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrAuroraSafeSink()).logZephyrAurora();
    }
}

class CWE117_P10_V2_ZephyrAuroraSafeSink {
    public void logZephyrAurora() {
        String data = CWE117_P10_V2_ZephyrAuroraSafe.data;
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
