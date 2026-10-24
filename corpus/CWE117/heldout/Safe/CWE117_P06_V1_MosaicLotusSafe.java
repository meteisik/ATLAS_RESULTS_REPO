import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicLotusSafe {

    public void handleMosaicLotus() {
        String data;
        data = System.getenv("MOSAIC_LOTUS_USER");
        (new CWE117_P06_V1_MosaicLotusSafeSink()).logMosaicLotus(data);
    }
}

class CWE117_P06_V1_MosaicLotusSafeSink {
    public void logMosaicLotus(String data) {
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
