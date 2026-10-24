import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicComet {

    public void handleMosaicComet() {
        String data;
        data = (new CWE117_P07_V1_MosaicCometSource()).readMosaicComet();
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicCometSource {
    public String readMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_USER");
        return data;
    }
}
