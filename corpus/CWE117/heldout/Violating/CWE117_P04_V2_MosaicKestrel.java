import java.util.logging.Logger;

public class CWE117_P04_V2_MosaicKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String readMosaicKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("MOSAIC_KESTREL_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleMosaicKestrel() {
        String data = readMosaicKestrel();
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + data);
    }
}
