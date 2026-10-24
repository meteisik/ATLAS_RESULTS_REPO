import java.util.logging.Logger;

public class CWE117_P05_V1_JadeGlintSafe {

    private String jadeGlintData;

    private void logJadeGlint() {
        String data = jadeGlintData;
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeGlint() {
        String data;
        data = System.getenv("JADE_GLINT_USER");
        jadeGlintData = data;
        logJadeGlint();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
