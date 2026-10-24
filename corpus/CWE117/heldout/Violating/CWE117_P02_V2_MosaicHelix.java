import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicHelix {

    public void handleMosaicHelix() {
        String dataCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = System.getenv("MOSAIC_HELIX_USER");
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicHelixLogger = Logger.getLogger("mosaicHelix.audit");
            mosaicHelixLogger.info("Login attempt for user " + data);
        }
    }
}
