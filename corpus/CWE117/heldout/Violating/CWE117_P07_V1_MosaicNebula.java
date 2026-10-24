import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicNebula {

    public void handleMosaicNebula() {
        String data;
        data = (new CWE117_P07_V1_MosaicNebulaSource()).readMosaicNebula();
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicNebulaSource {
    public String readMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_USER");
        return data;
    }
}
