import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicHarborSafe {

    private String mosaicHarborData;

    private void logMosaicHarbor() {
        String data = mosaicHarborData;
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicHarbor() {
        String data;
        data = System.getenv("MOSAIC_HARBOR_USER");
        mosaicHarborData = data;
        logMosaicHarbor();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
