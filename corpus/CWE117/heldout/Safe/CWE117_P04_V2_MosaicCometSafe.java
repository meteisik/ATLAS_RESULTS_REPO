import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicCometSafe {

    private String readMosaicComet() {
        String data;
        if (5 == 5) {
            data = System.getenv("MOSAIC_COMET_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicComet() {
        String data = readMosaicComet();
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
