import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryLotusSafe {

    private void logIvoryLotus(String data) {
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_USER");
        logIvoryLotus(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
