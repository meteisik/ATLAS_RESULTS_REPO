import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readMosaicOrbit() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("MOSAIC_ORBIT_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicOrbit() {
        String data = readMosaicOrbit();
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
