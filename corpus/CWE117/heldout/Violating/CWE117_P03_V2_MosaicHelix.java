import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicHelix {

    private void logMosaicHelix(String data) {
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicHelix() {
        String data;
        if (5 == 5) {
            data = System.getenv("MOSAIC_HELIX_USER");
        } else {
            data = null;
        }
        logMosaicHelix(data);
    }
}
