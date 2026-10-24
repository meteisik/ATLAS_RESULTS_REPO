import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetGlint {

    public void handleVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        CWE117_P12_V1_VelvetGlintBase baseObject = new CWE117_P12_V1_VelvetGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetGlintBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetGlintSink extends CWE117_P12_V1_VelvetGlintBase {
    public void action(String data) {
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + data);
    }
}
