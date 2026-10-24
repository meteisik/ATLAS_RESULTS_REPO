import java.util.logging.Logger;

public class CWE117_P06_V1_MosaicLotus {

    public void handleMosaicLotus() {
        String data;
        data = System.getenv("MOSAIC_LOTUS_USER");
        (new CWE117_P06_V1_MosaicLotusSink()).logMosaicLotus(data);
    }
}

class CWE117_P06_V1_MosaicLotusSink {
    public void logMosaicLotus(String data) {
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + data);
    }
}
