import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxHarborSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxHarborSafeSink()).logOnyxHarbor(dataContainer);
    }
}

class CWE117_P09_V1_OnyxHarborSafeSink {
    public void logOnyxHarbor(CWE117_P09_V1_OnyxHarborSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
