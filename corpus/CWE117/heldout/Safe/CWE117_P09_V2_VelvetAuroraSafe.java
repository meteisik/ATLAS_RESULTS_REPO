import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void handleVelvetAurora() {
        String data;
        if (5 == 5) {
            data = System.getenv("VELVET_AURORA_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetAuroraSafeSink()).logVelvetAurora(dataContainer);
    }
}

class CWE117_P09_V2_VelvetAuroraSafeSink {
    public void logVelvetAurora(CWE117_P09_V2_VelvetAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
