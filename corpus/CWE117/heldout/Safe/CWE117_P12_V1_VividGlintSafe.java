import java.util.logging.Logger;

public class CWE117_P12_V1_VividGlintSafe {

    public void handleVividGlint() {
        String data;
        data = System.getenv("VIVID_GLINT_USER");
        CWE117_P12_V1_VividGlintSafeBase baseObject = new CWE117_P12_V1_VividGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividGlintSafeSink extends CWE117_P12_V1_VividGlintSafeBase {
    public void action(String data) {
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
