import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetGlint {

    public void handleVelvetGlint() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_VelvetGlintSource()).readVelvetGlint();
        } else {
            data = null;
        }
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetGlintSource {
    public String readVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        return data;
    }
}
