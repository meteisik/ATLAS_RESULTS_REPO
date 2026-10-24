import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleMosaicOrbit() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = System.getenv("MOSAIC_ORBIT_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicOrbitLogger = Logger.getLogger("mosaicOrbit.audit");
            mosaicOrbitLogger.info("Login attempt for user " + data);
        }
    }
}
