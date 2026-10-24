import java.util.logging.Logger;

public class CWE117_P01_V1_AmberGlintSafe {

    public void handleAmberGlint() {
        String data;
        data = System.getenv("AMBER_GLINT_USER");
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
