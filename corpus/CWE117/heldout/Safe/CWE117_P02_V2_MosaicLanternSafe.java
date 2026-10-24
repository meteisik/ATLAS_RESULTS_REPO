import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicLanternSafe {

    public void handleMosaicLantern() {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("MOSAIC_LANTERN_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
            mosaicLanternLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
