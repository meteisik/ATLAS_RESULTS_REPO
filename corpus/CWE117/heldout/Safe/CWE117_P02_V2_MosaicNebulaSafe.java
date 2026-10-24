import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicNebulaSafe {
    private static boolean privateTrue = true;

    public void handleMosaicNebula() {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("MOSAIC_NEBULA_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicNebulaLogger = Logger.getLogger("mosaicNebula.audit");
            mosaicNebulaLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
