import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrSundial {

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
        (new CWE117_P10_V2_ZephyrSundialSink()).logZephyrSundial();
    }
}

class CWE117_P10_V2_ZephyrSundialSink {
    public void logZephyrSundial() {
        String data = CWE117_P10_V2_ZephyrSundial.data;
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + data);
    }
}
