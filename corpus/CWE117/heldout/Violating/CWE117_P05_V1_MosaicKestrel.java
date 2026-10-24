import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicKestrel {

    private String mosaicKestrelData;

    private void logMosaicKestrel() {
        String data = mosaicKestrelData;
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicKestrel() {
        String data;
        data = System.getenv("MOSAIC_KESTREL_USER");
        mosaicKestrelData = data;
        logMosaicKestrel();
    }
}
