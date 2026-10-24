import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicKestrelSafe {

    public void handleMosaicKestrel() {
        String data;
        data = (new CWE117_P07_V1_MosaicKestrelSafeSource()).readMosaicKestrel();
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicKestrelSafeSource {
    public String readMosaicKestrel() {
        String data;
        data = System.getenv("MOSAIC_KESTREL_USER");
        return data;
    }
}
