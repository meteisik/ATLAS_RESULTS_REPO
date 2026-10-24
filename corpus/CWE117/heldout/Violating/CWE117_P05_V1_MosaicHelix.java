import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicHelix {

    private String mosaicHelixData;

    private void logMosaicHelix() {
        String data = mosaicHelixData;
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicHelix() {
        String data;
        data = System.getenv("MOSAIC_HELIX_USER");
        mosaicHelixData = data;
        logMosaicHelix();
    }
}
