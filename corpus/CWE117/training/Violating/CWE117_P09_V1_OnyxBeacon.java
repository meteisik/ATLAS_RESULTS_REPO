import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxBeacon {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxBeacon() {
        String data;
        data = System.getenv("ONYX_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxBeaconSink()).logOnyxBeacon(dataContainer);
    }
}

class CWE117_P09_V1_OnyxBeaconSink {
    public void logOnyxBeacon(CWE117_P09_V1_OnyxBeacon.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + data);
    }
}
