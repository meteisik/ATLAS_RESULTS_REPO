import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxHelixSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxHelixSafeSink()).logOnyxHelix(dataContainer);
    }
}

class CWE117_P09_V1_OnyxHelixSafeSink {
    public void logOnyxHelix(CWE117_P09_V1_OnyxHelixSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
