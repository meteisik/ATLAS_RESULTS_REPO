import java.util.logging.Logger;

public class CWE117_P03_V2_MosaicKestrel {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void logMosaicKestrel(String data) {
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("MOSAIC_KESTREL_USER");
        } else {
            data = null;
        }
        logMosaicKestrel(data);
    }
}
