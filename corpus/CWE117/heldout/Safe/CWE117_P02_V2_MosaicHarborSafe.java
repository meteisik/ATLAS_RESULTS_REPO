import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicHarborSafe {

    public void handleMosaicHarbor() {
        String dataCopy;
        {
            String data;
            while (true) {
                data = System.getenv("MOSAIC_HARBOR_USER");
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
            mosaicHarborLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
