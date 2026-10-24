import java.util.logging.Logger;

public class CWE117_P09_V2_ArcticComet {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void handleArcticComet() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ARCTIC_COMET_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ArcticCometSink()).logArcticComet(dataContainer);
    }
}

class CWE117_P09_V2_ArcticCometSink {
    public void logArcticComet(CWE117_P09_V2_ArcticComet.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + data);
    }
}
