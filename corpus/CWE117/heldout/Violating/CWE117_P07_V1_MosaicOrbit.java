import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicOrbit {

    public void handleMosaicOrbit() {
        String data;
        data = (new CWE117_P07_V1_MosaicOrbitSource()).readMosaicOrbit();
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicOrbitSource {
    public String readMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_USER");
        return data;
    }
}
