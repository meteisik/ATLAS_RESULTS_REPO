import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicOrbitSafe {
    private static boolean privateReturnsTrue() { return true; }

    private void logMosaicOrbit(String data) {
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicOrbit() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("MOSAIC_ORBIT_USER");
        } else {
            data = null;
        }
        logMosaicOrbit(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
