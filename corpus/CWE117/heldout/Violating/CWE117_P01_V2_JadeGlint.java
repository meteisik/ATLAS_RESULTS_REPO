import java.util.logging.Logger;

public class CWE117_P01_V2_JadeGlint {

    public void handleJadeGlint() {
        String data;
        if (true) {
            data = System.getenv("JADE_GLINT_USER");
        } else {
            data = null;
        }
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + data);
    }
}
