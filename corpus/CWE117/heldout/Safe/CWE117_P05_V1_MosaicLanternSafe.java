import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicLanternSafe {

    private String mosaicLanternData;

    private void logMosaicLantern() {
        String data = mosaicLanternData;
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_USER");
        mosaicLanternData = data;
        logMosaicLantern();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
