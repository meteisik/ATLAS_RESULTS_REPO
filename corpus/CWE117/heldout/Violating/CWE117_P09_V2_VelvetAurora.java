import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetAurora {

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
        (new CWE117_P09_V2_VelvetAuroraSink()).logVelvetAurora(dataContainer);
    }
}

class CWE117_P09_V2_VelvetAuroraSink {
    public void logVelvetAurora(CWE117_P09_V2_VelvetAurora.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}
