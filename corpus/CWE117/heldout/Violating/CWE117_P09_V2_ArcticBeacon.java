import java.util.logging.Logger;

public class CWE117_P09_V2_ArcticBeacon {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void handleArcticBeacon() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_BEACON_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ArcticBeaconSink()).logArcticBeacon(dataContainer);
    }
}

class CWE117_P09_V2_ArcticBeaconSink {
    public void logArcticBeacon(CWE117_P09_V2_ArcticBeacon.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + data);
    }
}
