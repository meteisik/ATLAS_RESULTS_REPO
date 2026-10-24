import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicBeaconSafe {

    private String mosaicBeaconData;

    private void logMosaicBeacon() {
        String data = mosaicBeaconData;
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicBeacon() {
        String data;
        data = System.getenv("MOSAIC_BEACON_USER");
        mosaicBeaconData = data;
        logMosaicBeacon();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
