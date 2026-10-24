import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryLotus {

    private void logIvoryLotus(String data) {
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_USER");
        logIvoryLotus(data);
    }
}
