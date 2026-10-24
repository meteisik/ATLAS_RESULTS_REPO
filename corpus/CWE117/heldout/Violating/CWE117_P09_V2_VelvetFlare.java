import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetFlare {
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
        (new CWE117_P09_V2_VelvetFlareSink()).logVelvetFlare(dataContainer);
    }
}

class CWE117_P09_V2_VelvetFlareSink {
    public void logVelvetFlare(CWE117_P09_V2_VelvetFlare.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}
