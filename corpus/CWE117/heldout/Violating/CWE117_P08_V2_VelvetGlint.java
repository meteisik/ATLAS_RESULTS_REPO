import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetGlint {
    private static boolean privateTrue = true;

    public void handleVelvetGlint() {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_GLINT_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetGlintSink()).logVelvetGlint(dataArray);
    }
}

class CWE117_P08_V2_VelvetGlintSink {
    public void logVelvetGlint(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + data);
    }
}
