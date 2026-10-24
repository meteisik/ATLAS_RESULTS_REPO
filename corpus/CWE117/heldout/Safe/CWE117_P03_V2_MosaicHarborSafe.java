import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicHarborSafe {

    private void logMosaicHarbor(String data) {
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicHarbor() {
        String data;
        if (true) {
            data = System.getenv("MOSAIC_HARBOR_USER");
        } else {
            data = null;
        }
        logMosaicHarbor(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
