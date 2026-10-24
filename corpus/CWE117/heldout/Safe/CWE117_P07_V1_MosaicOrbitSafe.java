import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicOrbitSafe {

    public void handleMosaicOrbit() {
        String data;
        data = (new CWE117_P07_V1_MosaicOrbitSafeSource()).readMosaicOrbit();
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicOrbitSafeSource {
    public String readMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_USER");
        return data;
    }
}
