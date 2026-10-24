import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicHarborSafe {

    public void handleMosaicHarbor() {
        String data;
        data = System.getenv("MOSAIC_HARBOR_USER");
        (new CWE117_P06_V1_MosaicHarborSafeSink()).logMosaicHarbor(data);
    }
}

class CWE117_P06_V1_MosaicHarborSafeSink {
    public void logMosaicHarbor(String data) {
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
