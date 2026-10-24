import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logMosaicRaven(String data) {
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicRaven() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_RAVEN_USER");
        } else {
            data = null;
        }
        logMosaicRaven(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
