import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleMosaicLotus() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("MOSAIC_LOTUS_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
            mosaicLotusLogger.info("Login attempt for user " + data);
        }
    }
}
