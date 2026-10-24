import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicLanternSafe {

    public void handleMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_USER");
        (new CWE117_P06_V1_MosaicLanternSafeSink()).logMosaicLantern(data);
    }
}

class CWE117_P06_V1_MosaicLanternSafeSink {
    public void logMosaicLantern(String data) {
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
