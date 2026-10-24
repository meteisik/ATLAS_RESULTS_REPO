import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrGlintSafe {

    public void handleZephyrGlint() {
        String data;
        data = System.getenv("ZEPHYR_GLINT_USER");
        CWE117_P12_V1_ZephyrGlintSafeBase baseObject = new CWE117_P12_V1_ZephyrGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrGlintSafeSink extends CWE117_P12_V1_ZephyrGlintSafeBase {
    public void action(String data) {
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
