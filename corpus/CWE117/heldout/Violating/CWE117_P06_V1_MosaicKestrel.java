import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicKestrel {

    public void handleMosaicKestrel() {
        String data;
        data = System.getenv("MOSAIC_KESTREL_USER");
        (new CWE117_P06_V1_MosaicKestrelSink()).logMosaicKestrel(data);
    }
}

class CWE117_P06_V1_MosaicKestrelSink {
    public void logMosaicKestrel(String data) {
        Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
        mosaicKestrelLogger.info("Login attempt for user " + data);
    }
}
