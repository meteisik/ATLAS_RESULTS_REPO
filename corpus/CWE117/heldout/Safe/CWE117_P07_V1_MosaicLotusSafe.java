import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicLotusSafe {

    public void handleMosaicLotus() {
        String data;
        data = (new CWE117_P07_V1_MosaicLotusSafeSource()).readMosaicLotus();
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicLotusSafeSource {
    public String readMosaicLotus() {
        String data;
        data = System.getenv("MOSAIC_LOTUS_USER");
        return data;
    }
}
