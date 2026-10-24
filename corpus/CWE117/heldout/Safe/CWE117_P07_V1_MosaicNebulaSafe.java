import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicNebulaSafe {

    public void handleMosaicNebula() {
        String data;
        data = (new CWE117_P07_V1_MosaicNebulaSafeSource()).readMosaicNebula();
        Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
        mosaicNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicNebulaSafeSource {
    public String readMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_USER");
        return data;
    }
}
