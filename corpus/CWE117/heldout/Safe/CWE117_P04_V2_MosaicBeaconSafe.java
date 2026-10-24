import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicBeaconSafe {

    private String readMosaicBeacon() {
        String data;
        if (true) {
            data = System.getenv("MOSAIC_BEACON_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicBeacon() {
        String data = readMosaicBeacon();
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
