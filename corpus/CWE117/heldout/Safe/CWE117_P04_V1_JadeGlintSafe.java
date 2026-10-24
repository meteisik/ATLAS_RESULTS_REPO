import java.util.logging.Logger;

public class CWE117_P04_V1_JadeGlintSafe {

    private String readJadeGlint() {
        String data;
        data = System.getenv("JADE_GLINT_USER");
        return data;
    }

    public void handleJadeGlint() {
        String data = readJadeGlint();
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
