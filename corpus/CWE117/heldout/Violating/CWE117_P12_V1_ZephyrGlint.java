import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrGlint {

    public void handleZephyrGlint() {
        String data;
        data = System.getenv("ZEPHYR_GLINT_USER");
        CWE117_P12_V1_ZephyrGlintBase baseObject = new CWE117_P12_V1_ZephyrGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrGlintBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrGlintSink extends CWE117_P12_V1_ZephyrGlintBase {
    public void action(String data) {
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + data);
    }
}
