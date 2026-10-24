import java.util.logging.Logger;

public class CWE117_P12_V1_AmberGlintSafe {

    public void handleAmberGlint() {
        String data;
        data = System.getenv("AMBER_GLINT_USER");
        CWE117_P12_V1_AmberGlintSafeBase baseObject = new CWE117_P12_V1_AmberGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberGlintSafeSink extends CWE117_P12_V1_AmberGlintSafeBase {
    public void action(String data) {
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
