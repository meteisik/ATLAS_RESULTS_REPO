import java.util.logging.Logger;

public class CWE117_P02_V2_MosaicRaven {
    private static int privateFive = 5;

    public void handleMosaicRaven() {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("MOSAIC_RAVEN_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
            mosaicRavenLogger.info("Login attempt for user " + data);
        }
    }
}
