import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicOrbitSafe {

    private String mosaicOrbitData;

    private void logMosaicOrbit() {
        String data = mosaicOrbitData;
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_USER");
        mosaicOrbitData = data;
        logMosaicOrbit();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
