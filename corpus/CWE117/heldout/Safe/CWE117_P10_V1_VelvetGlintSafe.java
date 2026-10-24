import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetGlintSafe {

    public static String data;

    public void handleVelvetGlint() {
        data = System.getenv("VELVET_GLINT_USER");
        (new CWE117_P10_V1_VelvetGlintSafeSink()).logVelvetGlint();
    }
}

class CWE117_P10_V1_VelvetGlintSafeSink {
    public void logVelvetGlint() {
        String data = CWE117_P10_V1_VelvetGlintSafe.data;
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
