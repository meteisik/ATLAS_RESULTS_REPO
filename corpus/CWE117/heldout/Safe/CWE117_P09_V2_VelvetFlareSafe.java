import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void handleVelvetFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_FLARE_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetFlareSafeSink()).logVelvetFlare(dataContainer);
    }
}

class CWE117_P09_V2_VelvetFlareSafeSink {
    public void logVelvetFlare(CWE117_P09_V2_VelvetFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
