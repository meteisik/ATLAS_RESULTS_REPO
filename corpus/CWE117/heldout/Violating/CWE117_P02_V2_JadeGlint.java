import java.util.logging.Logger;

public class CWE117_P02_V2_JadeGlint {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleJadeGlint() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("JADE_GLINT_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeGlintLogger = Logger.getLogger("jadeGlint.audit");
            jadeGlintLogger.info("Login attempt for user " + data);
        }
    }
}
