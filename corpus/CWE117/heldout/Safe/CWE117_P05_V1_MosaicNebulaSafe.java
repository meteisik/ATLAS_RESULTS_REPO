import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicNebulaSafe {

    private String mosaicNebulaData;

    private void logMosaicNebula() {
        String data = mosaicNebulaData;
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_USER");
        mosaicNebulaData = data;
        logMosaicNebula();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
