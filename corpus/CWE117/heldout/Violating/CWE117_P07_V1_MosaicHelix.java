import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicHelix {

    public void handleMosaicHelix() {
        String data;
        data = (new CWE117_P07_V1_MosaicHelixSource()).readMosaicHelix();
        Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
        mosaicHelixLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicHelixSource {
    public String readMosaicHelix() {
        String data;
        data = System.getenv("MOSAIC_HELIX_USER");
        return data;
    }
}
