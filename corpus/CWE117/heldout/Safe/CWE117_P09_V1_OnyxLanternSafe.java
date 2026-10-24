import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxLantern() {
        String data;
        data = System.getenv("ONYX_LANTERN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxLanternSafeSink()).logOnyxLantern(dataContainer);
    }
}

class CWE117_P09_V1_OnyxLanternSafeSink {
    public void logOnyxLantern(CWE117_P09_V1_OnyxLanternSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
