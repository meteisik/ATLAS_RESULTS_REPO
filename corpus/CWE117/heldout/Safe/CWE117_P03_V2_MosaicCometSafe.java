import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicCometSafe {

    private void logMosaicComet(String data) {
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicComet() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("MOSAIC_COMET_USER");
        }
        logMosaicComet(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
