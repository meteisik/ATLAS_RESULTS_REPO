import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicHarborSafe {

    public void handleMosaicHarbor() {
        String data;
        data = (new CWE117_P07_V1_MosaicHarborSafeSource()).readMosaicHarbor();
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicHarborSafeSource {
    public String readMosaicHarbor() {
        String data;
        data = System.getenv("MOSAIC_HARBOR_USER");
        return data;
    }
}
