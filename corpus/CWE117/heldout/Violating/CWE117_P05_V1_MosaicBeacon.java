import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicBeacon {

    private String mosaicBeaconData;

    private void logMosaicBeacon() {
        String data = mosaicBeaconData;
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicBeacon() {
        String data;
        data = System.getenv("MOSAIC_BEACON_USER");
        mosaicBeaconData = data;
        logMosaicBeacon();
    }
}
