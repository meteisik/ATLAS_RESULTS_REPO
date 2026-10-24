import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicLantern {

    public void handleMosaicLantern() {
        String data;
        data = (new CWE117_P07_V1_MosaicLanternSource()).readMosaicLantern();
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicLanternSource {
    public String readMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_USER");
        return data;
    }
}
