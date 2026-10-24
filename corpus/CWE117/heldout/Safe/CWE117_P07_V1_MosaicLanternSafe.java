import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicLanternSafe {

    public void handleMosaicLantern() {
        String data;
        data = (new CWE117_P07_V1_MosaicLanternSafeSource()).readMosaicLantern();
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicLanternSafeSource {
    public String readMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_USER");
        return data;
    }
}
