import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronFlare() {
        String data;
        data = System.getenv("SAFFRON_FLARE_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronFlareSafeSink()).logSaffronFlare(dataContainer);
    }
}

class CWE117_P09_V1_SaffronFlareSafeSink {
    public void logSaffronFlare(CWE117_P09_V1_SaffronFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
