import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicLotusSafe {
    private static boolean privateReturnsTrue() { return true; }

    private String readMosaicLotus() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_LOTUS_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicLotus() {
        String data = readMosaicLotus();
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
