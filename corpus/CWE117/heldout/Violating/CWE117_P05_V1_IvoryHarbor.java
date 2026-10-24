import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryHarbor {

    private String ivoryHarborData;

    private void logIvoryHarbor() {
        String data = ivoryHarborData;
        Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
        ivoryHarborLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryHarbor() {
        String data;
        data = System.getenv("IVORY_HARBOR_USER");
        ivoryHarborData = data;
        logIvoryHarbor();
    }
}
