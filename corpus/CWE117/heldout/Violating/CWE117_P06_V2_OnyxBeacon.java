import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxBeacon {

    public void handleOnyxBeacon() {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_BEACON_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxBeaconSink()).logOnyxBeacon(data);
    }
}

class CWE117_P06_V2_OnyxBeaconSink {
    public void logOnyxBeacon(String data) {
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + data);
    }
}
