import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrSundialSafe {

    public static String data;

    public void handleZephyrSundial() {
        switch (7) {
        case 7:
            data = System.getenv("ZEPHYR_SUNDIAL_USER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE117_P10_V2_ZephyrSundialSafeSink()).logZephyrSundial();
    }
}

class CWE117_P10_V2_ZephyrSundialSafeSink {
    public void logZephyrSundial() {
        String data = CWE117_P10_V2_ZephyrSundialSafe.data;
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
