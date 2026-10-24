import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxKestrelSafeSink()).logOnyxKestrel(dataContainer);
    }
}

class CWE117_P09_V1_OnyxKestrelSafeSink {
    public void logOnyxKestrel(CWE117_P09_V1_OnyxKestrelSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
