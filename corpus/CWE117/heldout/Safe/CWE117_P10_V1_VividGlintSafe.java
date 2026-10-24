import java.util.logging.Logger;

public class CWE117_P10_V1_VividGlintSafe {

    public static String data;

    public void handleVividGlint() {
        data = System.getenv("VIVID_GLINT_USER");
        (new CWE117_P10_V1_VividGlintSafeSink()).logVividGlint();
    }
}

class CWE117_P10_V1_VividGlintSafeSink {
    public void logVividGlint() {
        String data = CWE117_P10_V1_VividGlintSafe.data;
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
