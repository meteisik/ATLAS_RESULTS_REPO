import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicNebulaSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readMosaicNebula() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_NEBULA_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicNebula() {
        String data = readMosaicNebula();
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
