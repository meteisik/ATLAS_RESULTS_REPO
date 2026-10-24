import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicLotus {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void logMosaicLotus(String data) {
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("MOSAIC_LOTUS_USER");
        } else {
            data = null;
        }
        logMosaicLotus(data);
    }
}
