import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetGlintSafe {

    public void handleVelvetGlint() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_VelvetGlintSafeSource()).readVelvetGlint();
        } else {
            data = null;
        }
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetGlintSafeSource {
    public String readVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        return data;
    }
}
