import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicBeacon {

    public void handleMosaicBeacon() {
        String data;
        data = System.getenv("MOSAIC_BEACON_USER");
        (new CWE117_P06_V1_MosaicBeaconSink()).logMosaicBeacon(data);
    }
}

class CWE117_P06_V1_MosaicBeaconSink {
    public void logMosaicBeacon(String data) {
        Logger mosaicBeaconLogger = Logger.getLogger("mosaicBeacon.audit");
        mosaicBeaconLogger.info("Login attempt for user " + data);
    }
}
