import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicComet {

    private String mosaicCometData;

    private void logMosaicComet() {
        String data = mosaicCometData;
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_USER");
        mosaicCometData = data;
        logMosaicComet();
    }
}
