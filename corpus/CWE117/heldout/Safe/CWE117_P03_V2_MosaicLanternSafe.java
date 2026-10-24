import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicLanternSafe {
    private static boolean privateTrue = true;

    private void logMosaicLantern(String data) {
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicLantern() {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_LANTERN_USER");
        } else {
            data = null;
        }
        logMosaicLantern(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
