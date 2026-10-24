import java.util.logging.Logger;

public class CWE117_P05_V1_JadeGlint {

    private String jadeGlintData;

    private void logJadeGlint() {
        String data = jadeGlintData;
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + data);
    }

    public void handleJadeGlint() {
        String data;
        data = System.getenv("JADE_GLINT_USER");
        jadeGlintData = data;
        logJadeGlint();
    }
}
