import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicComet {

    public void handleMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_USER");
        (new CWE117_P06_V1_MosaicCometSink()).logMosaicComet(data);
    }
}

class CWE117_P06_V1_MosaicCometSink {
    public void logMosaicComet(String data) {
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + data);
    }
}
