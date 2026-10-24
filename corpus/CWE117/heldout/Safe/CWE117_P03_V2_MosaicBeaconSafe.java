import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicBeaconSafe {

    private void logMosaicBeacon(String data) {
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicBeacon() {
        String data;
        while (true) {
            data = System.getenv("MOSAIC_BEACON_USER");
            break;
        }
        logMosaicBeacon(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
