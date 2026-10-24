import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrAurora {
    private static boolean privateTrue = true;

    public static String data;

    public void handleZephyrAurora() {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrAuroraSink()).logZephyrAurora();
    }
}

class CWE117_P10_V2_ZephyrAuroraSink {
    public void logZephyrAurora() {
        String data = CWE117_P10_V2_ZephyrAurora.data;
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + data);
    }
}
