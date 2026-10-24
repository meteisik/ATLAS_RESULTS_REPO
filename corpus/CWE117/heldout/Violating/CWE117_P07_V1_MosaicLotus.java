import java.util.logging.Logger;

public class CWE117_P07_V1_MosaicLotus {

    public void handleMosaicLotus() {
        String data;
        data = (new CWE117_P07_V1_MosaicLotusSource()).readMosaicLotus();
        Logger mosaicLotusLogger = Logger.getLogger("mosaicLotus.audit");
        mosaicLotusLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_MosaicLotusSource {
    public String readMosaicLotus() {
        String data;
        data = System.getenv("MOSAIC_LOTUS_USER");
        return data;
    }
}
