import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicOrbitSafe {

    public void handleMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_USER");
        (new CWE117_P06_V1_MosaicOrbitSafeSink()).logMosaicOrbit(data);
    }
}

class CWE117_P06_V1_MosaicOrbitSafeSink {
    public void logMosaicOrbit(String data) {
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
