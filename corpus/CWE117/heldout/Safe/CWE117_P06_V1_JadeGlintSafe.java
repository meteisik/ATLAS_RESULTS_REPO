import java.util.logging.Logger;

public class CWE117_P06_V1_JadeGlintSafe {

    public void handleJadeGlint() {
        String data;
        data = System.getenv("JADE_GLINT_USER");
        (new CWE117_P06_V1_JadeGlintSafeSink()).logJadeGlint(data);
    }
}

class CWE117_P06_V1_JadeGlintSafeSink {
    public void logJadeGlint(String data) {
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
