import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrCascadeSafe {

    public void handleZephyrCascade() {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_USER");
        CWE117_P12_V1_ZephyrCascadeSafeBase baseObject = new CWE117_P12_V1_ZephyrCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrCascadeSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrCascadeSafeSink extends CWE117_P12_V1_ZephyrCascadeSafeBase {
    public void action(String data) {
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
