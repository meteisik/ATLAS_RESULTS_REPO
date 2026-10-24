import java.util.logging.Logger;

public class CWE117_P09_V2_ArcticCometSafe {
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
        (new CWE117_P09_V2_ArcticCometSafeSink()).logArcticComet(dataContainer);
    }
}

class CWE117_P09_V2_ArcticCometSafeSink {
    public void logArcticComet(CWE117_P09_V2_ArcticCometSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
