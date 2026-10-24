import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryLotusSafe {

    private String ivoryLotusData;

    private void logIvoryLotus() {
        String data = ivoryLotusData;
        Logger ivoryLotusLogger = Logger.getLogger("ivoryLotus.audit");
        ivoryLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_USER");
        ivoryLotusData = data;
        logIvoryLotus();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
