import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void handleVelvetMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_MANTIS_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetMantisSink()).logVelvetMantis(dataContainer);
    }
}

class CWE117_P09_V2_VelvetMantisSink {
    public void logVelvetMantis(CWE117_P09_V2_VelvetMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + data);
    }
}
