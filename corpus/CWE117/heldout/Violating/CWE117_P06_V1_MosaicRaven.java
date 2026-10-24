import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicRaven {

    public void handleMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_USER");
        (new CWE117_P06_V1_MosaicRavenSink()).logMosaicRaven(data);
    }
}

class CWE117_P06_V1_MosaicRavenSink {
    public void logMosaicRaven(String data) {
        Logger mosaicRavenLogger = Logger.getLogger("mosaicRaven.audit");
        mosaicRavenLogger.info("Login attempt for user " + data);
    }
}
