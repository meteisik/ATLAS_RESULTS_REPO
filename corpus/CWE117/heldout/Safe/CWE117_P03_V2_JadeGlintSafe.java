import java.util.logging.Logger;

public class CWE117_P03_V2_JadeGlintSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void logJadeGlint(String data) {
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeGlint() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_GLINT_USER");
        } else {
            data = null;
        }
        logJadeGlint(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
