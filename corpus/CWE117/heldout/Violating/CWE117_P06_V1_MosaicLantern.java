import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicLantern {

    public void handleMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_USER");
        (new CWE117_P06_V1_MosaicLanternSink()).logMosaicLantern(data);
    }
}

class CWE117_P06_V1_MosaicLanternSink {
    public void logMosaicLantern(String data) {
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + data);
    }
}
