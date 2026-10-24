import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicOrbit {
    private static boolean privateReturnsTrue() { return true; }

    private void logMosaicOrbit(String data) {
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + data);
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
}
