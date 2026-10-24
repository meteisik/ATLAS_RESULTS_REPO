import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicRaven {

    public void handleMosaicRaven() {
        String data;
        data = (new CWE117_P07_V1_MosaicRavenSource()).readMosaicRaven();
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicRavenSource {
    public String readMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        return data;
    }
}
