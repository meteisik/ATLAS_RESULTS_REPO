import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicKestrel {

    public void handleMosaicKestrel() {
        String data;
        data = (new CWE117_P07_V1_MosaicKestrelSource()).readMosaicKestrel();
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicKestrelSource {
    public String readMosaicKestrel() {
        String data;
        data = System.getenv("MOSAIC_KESTREL_USER");
        return data;
    }
}
