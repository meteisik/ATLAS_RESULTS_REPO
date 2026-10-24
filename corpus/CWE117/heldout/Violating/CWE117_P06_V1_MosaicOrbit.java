import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicOrbit {

    public void handleMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_USER");
        (new CWE117_P06_V1_MosaicOrbitSink()).logMosaicOrbit(data);
    }
}

class CWE117_P06_V1_MosaicOrbitSink {
    public void logMosaicOrbit(String data) {
        Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
        mosaicOrbitLogger.info("Login attempt for user " + data);
    }
}
