import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicRaven {

    private String mosaicRavenData;

    private void logMosaicRaven() {
        String data = mosaicRavenData;
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + data);
    }

    public void handleMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        mosaicRavenData = data;
        logMosaicRaven();
    }
}
