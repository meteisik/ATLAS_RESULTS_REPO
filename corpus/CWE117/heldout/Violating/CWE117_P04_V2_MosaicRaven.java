import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readMosaicRaven() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("MOSAIC_RAVEN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicRaven() {
        String data = readMosaicRaven();
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + data);
    }
}
