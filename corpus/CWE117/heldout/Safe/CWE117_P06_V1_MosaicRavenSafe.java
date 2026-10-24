import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicRavenSafe {

    public void handleMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        (new CWE117_P06_V1_MosaicRavenSafeSink()).logMosaicRaven(data);
    }
}

class CWE117_P06_V1_MosaicRavenSafeSink {
    public void logMosaicRaven(String data) {
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
