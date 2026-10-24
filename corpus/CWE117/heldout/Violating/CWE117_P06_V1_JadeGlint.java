import java.util.logging.Logger;

public class CWE117_P06_V1_JadeGlint {

    public void handleJadeGlint() {
        String data;
        data = System.getenv("JADE_GLINT_USER");
        (new CWE117_P06_V1_JadeGlintSink()).logJadeGlint(data);
    }
}

class CWE117_P06_V1_JadeGlintSink {
    public void logJadeGlint(String data) {
        Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
        jadeGlintLogger.info("Login attempt for user " + data);
    }
}
