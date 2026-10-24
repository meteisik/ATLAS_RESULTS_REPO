import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronCascadeSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronCascade() {
        String data;
        data = System.getenv("SAFFRON_CASCADE_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronCascadeSafeSink()).logSaffronCascade(dataContainer);
    }
}

class CWE117_P09_V1_SaffronCascadeSafeSink {
    public void logSaffronCascade(CWE117_P09_V1_SaffronCascadeSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
