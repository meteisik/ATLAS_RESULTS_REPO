import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryLotus {

    private String ivoryLotusData;

    private void logIvoryLotus() {
        String data = ivoryLotusData;
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_USER");
        ivoryLotusData = data;
        logIvoryLotus();
    }
}
