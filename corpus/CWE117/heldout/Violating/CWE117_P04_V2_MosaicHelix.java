import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicHelix {
    private static boolean privateTrue = true;

    private String readMosaicHelix() {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_HELIX_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicHelix() {
        String data = readMosaicHelix();
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + data);
    }
}
