import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicKestrelSafe {

    public void handleMosaicKestrel() {
        String data;
        data = System.getenv("MOSAIC_KESTREL_USER");
        (new CWE117_P06_V1_MosaicKestrelSafeSink()).logMosaicKestrel(data);
    }
}

class CWE117_P06_V1_MosaicKestrelSafeSink {
    public void logMosaicKestrel(String data) {
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
