import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetGlint {

    public static String data;

    public void handleVelvetGlint() {
        data = System.getenv("VELVET_GLINT_USER");
        (new CWE117_P10_V1_VelvetGlintSink()).logVelvetGlint();
    }
}

class CWE117_P10_V1_VelvetGlintSink {
    public void logVelvetGlint() {
        String data = CWE117_P10_V1_VelvetGlint.data;
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + data);
    }
}
