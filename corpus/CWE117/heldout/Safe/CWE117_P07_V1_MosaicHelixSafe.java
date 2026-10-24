import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicHelixSafe {

    public void handleMosaicHelix() {
        String data;
        data = (new CWE117_P07_V1_MosaicHelixSafeSource()).readMosaicHelix();
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicHelixSafeSource {
    public String readMosaicHelix() {
        String data;
        data = System.getenv("MOSAIC_HELIX_USER");
        return data;
    }
}
