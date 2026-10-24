import java.util.logging.Logger;

public class CWE117_P10_V2_AmberGlintSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void handleAmberGlint() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_GLINT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberGlintSafeSink()).logAmberGlint();
    }
}

class CWE117_P10_V2_AmberGlintSafeSink {
    public void logAmberGlint() {
        String data = CWE117_P10_V2_AmberGlintSafe.data;
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
