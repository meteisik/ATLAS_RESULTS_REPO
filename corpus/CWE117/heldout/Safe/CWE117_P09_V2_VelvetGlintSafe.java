import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetGlintSafe {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void handleVelvetGlint() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_GLINT_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetGlintSafeSink()).logVelvetGlint(dataContainer);
    }
}

class CWE117_P09_V2_VelvetGlintSafeSink {
    public void logVelvetGlint(CWE117_P09_V2_VelvetGlintSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
