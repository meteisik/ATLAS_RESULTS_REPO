import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrMantisSafe {

    public void handleZephyrMantis() {
        String data;
        data = System.getenv("ZEPHYR_MANTIS_USER");
        CWE117_P12_V1_ZephyrMantisSafeBase baseObject = new CWE117_P12_V1_ZephyrMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrMantisSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrMantisSafeSink extends CWE117_P12_V1_ZephyrMantisSafeBase {
    public void action(String data) {
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
