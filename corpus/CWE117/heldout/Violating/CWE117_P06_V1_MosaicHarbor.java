import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicHarbor {

    public void handleMosaicHarbor() {
        String data;
        data = System.getenv("MOSAIC_HARBOR_USER");
        (new CWE117_P06_V1_MosaicHarborSink()).logMosaicHarbor(data);
    }
}

class CWE117_P06_V1_MosaicHarborSink {
    public void logMosaicHarbor(String data) {
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + data);
    }
}
