import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrSundialSafe {

    public void handleZephyrSundial() {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_USER");
        CWE117_P12_V1_ZephyrSundialSafeBase baseObject = new CWE117_P12_V1_ZephyrSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrSundialSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrSundialSafeSink extends CWE117_P12_V1_ZephyrSundialSafeBase {
    public void action(String data) {
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
