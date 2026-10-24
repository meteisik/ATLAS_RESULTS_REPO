import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicCometSafe {

    public void handleMosaicComet() {
        String dataCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = System.getenv("MOSAIC_COMET_USER");
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
            mosaicCometLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
