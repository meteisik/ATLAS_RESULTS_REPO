import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrQuartzSafe {

    public void handleZephyrQuartz() {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_USER");
        CWE117_P12_V1_ZephyrQuartzSafeBase baseObject = new CWE117_P12_V1_ZephyrQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrQuartzSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrQuartzSafeSink extends CWE117_P12_V1_ZephyrQuartzSafeBase {
    public void action(String data) {
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
