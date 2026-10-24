import java.util.logging.Logger;

public class CWE117_P09_V2_AmberFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void handleAmberFlare() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_FLARE_USER");
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberFlareSafeSink()).logAmberFlare(dataContainer);
    }
}

class CWE117_P09_V2_AmberFlareSafeSink {
    public void logAmberFlare(CWE117_P09_V2_AmberFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
