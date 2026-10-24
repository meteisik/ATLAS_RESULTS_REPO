import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicRavenSafe {

    public void handleMosaicRaven() {
        String data;
        data = (new CWE117_P07_V1_MosaicRavenSafeSource()).readMosaicRaven();
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicRavenSafeSource {
    public String readMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        return data;
    }
}
