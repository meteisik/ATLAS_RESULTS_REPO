import java.util.logging.Logger;

public class CWE117_P05_V1_MosaicRavenSafe {

    private String mosaicRavenData;

    private void logMosaicRaven() {
        String data = mosaicRavenData;
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        mosaicRavenData = data;
        logMosaicRaven();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
