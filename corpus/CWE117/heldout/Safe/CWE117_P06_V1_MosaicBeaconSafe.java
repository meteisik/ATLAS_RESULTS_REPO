import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicBeaconSafe {

    public void handleMosaicBeacon() {
        String data;
        data = System.getenv("MOSAIC_BEACON_USER");
        (new CWE117_P06_V1_MosaicBeaconSafeSink()).logMosaicBeacon(data);
    }
}

class CWE117_P06_V1_MosaicBeaconSafeSink {
    public void logMosaicBeacon(String data) {
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
