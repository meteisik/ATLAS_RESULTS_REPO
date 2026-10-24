import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicNebula {

    public void handleMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_USER");
        (new CWE117_P06_V1_MosaicNebulaSink()).logMosaicNebula(data);
    }
}

class CWE117_P06_V1_MosaicNebulaSink {
    public void logMosaicNebula(String data) {
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + data);
    }
}
