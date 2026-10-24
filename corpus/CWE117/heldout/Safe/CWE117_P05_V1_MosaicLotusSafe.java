import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicLotusSafe {

    private String mosaicLotusData;

    private void logMosaicLotus() {
        String data = mosaicLotusData;
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicLotus() {
        String data;
        data = System.getenv("MOSAIC_LOTUS_USER");
        mosaicLotusData = data;
        logMosaicLotus();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
