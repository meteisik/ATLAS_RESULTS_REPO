import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryLotus {

    private String readIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_USER");
        return data;
    }

    public void handleIvoryLotus() {
        String data = readIvoryLotus();
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + data);
    }
}
