import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetCascade {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void handleVelvetCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_CASCADE_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetCascadeSink()).logVelvetCascade(dataContainer);
    }
}

class CWE117_P09_V2_VelvetCascadeSink {
    public void logVelvetCascade(CWE117_P09_V2_VelvetCascade.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}
