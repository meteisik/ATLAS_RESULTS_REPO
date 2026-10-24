import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicCometSafe {

    public void handleMosaicComet() {
        String data;
        data = (new CWE117_P07_V1_MosaicCometSafeSource()).readMosaicComet();
        Logger mosaicCometLogger = Logger.getLogger("mosaicComet.audit");
        mosaicCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_MosaicCometSafeSource {
    public String readMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_USER");
        return data;
    }
}
