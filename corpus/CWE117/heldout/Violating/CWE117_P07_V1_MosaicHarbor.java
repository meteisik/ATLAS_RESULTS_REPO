import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicHarbor {

    public void handleMosaicHarbor() {
        String data;
        data = (new CWE117_P07_V1_MosaicHarborSource()).readMosaicHarbor();
        Logger mosaicHarborLogger = Logger.getLogger("mosaicHarbor.audit");
        mosaicHarborLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicHarborSource {
    public String readMosaicHarbor() {
        String data;
        data = System.getenv("MOSAIC_HARBOR_USER");
        return data;
    }
}
