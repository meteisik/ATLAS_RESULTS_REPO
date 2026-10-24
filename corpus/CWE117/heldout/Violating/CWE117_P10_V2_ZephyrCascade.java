import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrCascade {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void handleZephyrCascade() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_CASCADE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrCascadeSink()).logZephyrCascade();
    }
}

class CWE117_P10_V2_ZephyrCascadeSink {
    public void logZephyrCascade() {
        String data = CWE117_P10_V2_ZephyrCascade.data;
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + data);
    }
}
