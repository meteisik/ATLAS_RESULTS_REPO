import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicHelix {

    public void handleMosaicHelix() {
        String data;
        data = System.getenv("MOSAIC_HELIX_USER");
        (new CWE117_P06_V1_MosaicHelixSink()).logMosaicHelix(data);
    }
}

class CWE117_P06_V1_MosaicHelixSink {
    public void logMosaicHelix(String data) {
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + data);
    }
}
