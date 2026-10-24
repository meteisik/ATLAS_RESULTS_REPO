import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicLantern {
    private static int privateFive = 5;

    private String readMosaicLantern() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("MOSAIC_LANTERN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicLantern() {
        String data = readMosaicLantern();
        Logger mosaicLanternLogger = Logger.getLogger("mosaicLantern.audit");
        mosaicLanternLogger.info("Login attempt for user " + data);
    }
}
