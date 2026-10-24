import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetGlintSafe {

    public void handleVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        CWE117_P12_V1_VelvetGlintSafeBase baseObject = new CWE117_P12_V1_VelvetGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetGlintSafeSink extends CWE117_P12_V1_VelvetGlintSafeBase {
    public void action(String data) {
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
