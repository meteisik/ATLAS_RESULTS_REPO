import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicBeacon {

    private void logMosaicBeacon(String data) {
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicBeacon() {
        String data;
        while (true) {
            data = System.getenv("MOSAIC_BEACON_USER");
            break;
        }
        logMosaicBeacon(data);
    }
}
