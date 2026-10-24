import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrPrismSafe {

    public void handleZephyrPrism() {
        String data;
        data = System.getenv("ZEPHYR_PRISM_USER");
        CWE117_P12_V1_ZephyrPrismSafeBase baseObject = new CWE117_P12_V1_ZephyrPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrPrismSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrPrismSafeSink extends CWE117_P12_V1_ZephyrPrismSafeBase {
    public void action(String data) {
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
