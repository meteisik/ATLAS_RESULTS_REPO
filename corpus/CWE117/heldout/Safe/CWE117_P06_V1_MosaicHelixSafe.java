import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicHelixSafe {

    public void handleMosaicHelix() {
        String data;
        data = System.getenv("MOSAIC_HELIX_USER");
        (new CWE117_P06_V1_MosaicHelixSafeSink()).logMosaicHelix(data);
    }
}

class CWE117_P06_V1_MosaicHelixSafeSink {
    public void logMosaicHelix(String data) {
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
