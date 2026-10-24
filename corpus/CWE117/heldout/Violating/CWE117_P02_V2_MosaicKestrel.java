import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicKestrel {

    public void handleMosaicKestrel() {
        String dataCopy;
        {
            String data;
            if (true) {
                data = System.getenv("MOSAIC_KESTREL_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicKestrelLogger = Logger.getLogger("mosaicKestrel.audit");
            mosaicKestrelLogger.info("Login attempt for user " + data);
        }
    }
}
