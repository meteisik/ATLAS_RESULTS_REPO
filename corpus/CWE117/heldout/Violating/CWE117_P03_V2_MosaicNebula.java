import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicNebula {
    private static int privateFive = 5;

    private void logMosaicNebula(String data) {
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicNebula() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("MOSAIC_NEBULA_USER");
        } else {
            data = null;
        }
        logMosaicNebula(data);
    }
}
