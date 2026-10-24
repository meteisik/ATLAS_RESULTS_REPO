import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxBeaconSafe {

    public void handleOnyxBeacon() {
        String data;
        data = System.getenv("ONYX_BEACON_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxBeaconSafeSink()).logOnyxBeacon(dataArray);
    }
}

class CWE117_P08_V1_OnyxBeaconSafeSink {
    public void logOnyxBeacon(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
