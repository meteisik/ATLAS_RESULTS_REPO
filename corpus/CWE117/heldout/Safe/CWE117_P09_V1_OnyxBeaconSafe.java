import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxBeacon() {
        String data;
        data = System.getenv("ONYX_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxBeaconSafeSink()).logOnyxBeacon(dataContainer);
    }
}

class CWE117_P09_V1_OnyxBeaconSafeSink {
    public void logOnyxBeacon(CWE117_P09_V1_OnyxBeaconSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
