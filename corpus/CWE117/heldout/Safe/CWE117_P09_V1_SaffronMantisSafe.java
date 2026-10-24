import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronMantisSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronMantisSafeSink()).logSaffronMantis(dataContainer);
    }
}

class CWE117_P09_V1_SaffronMantisSafeSink {
    public void logSaffronMantis(CWE117_P09_V1_SaffronMantisSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
