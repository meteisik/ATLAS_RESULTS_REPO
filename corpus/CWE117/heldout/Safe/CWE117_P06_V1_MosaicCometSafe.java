import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicCometSafe {

    public void handleMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_USER");
        (new CWE117_P06_V1_MosaicCometSafeSink()).logMosaicComet(data);
    }
}

class CWE117_P06_V1_MosaicCometSafeSink {
    public void logMosaicComet(String data) {
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
