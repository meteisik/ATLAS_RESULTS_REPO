import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicNebulaSafe {

    public void handleMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_USER");
        (new CWE117_P06_V1_MosaicNebulaSafeSink()).logMosaicNebula(data);
    }
}

class CWE117_P06_V1_MosaicNebulaSafeSink {
    public void logMosaicNebula(String data) {
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
