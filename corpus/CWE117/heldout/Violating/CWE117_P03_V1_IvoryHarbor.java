import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryHarbor {

    private void logIvoryHarbor(String data) {
        Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
        ivoryHarborLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryHarbor() {
        String data;
        data = System.getenv("IVORY_HARBOR_USER");
        logIvoryHarbor(data);
    }
}
