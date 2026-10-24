import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicHarbor {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String readMosaicHarbor() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_HARBOR_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicHarbor() {
        String data = readMosaicHarbor();
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + data);
    }
}
