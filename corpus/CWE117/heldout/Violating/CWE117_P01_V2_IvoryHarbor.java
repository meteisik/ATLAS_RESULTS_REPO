import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryHarbor {
    private static boolean privateTrue = true;

    public void handleIvoryHarbor() {
        String data;
        if (privateTrue) {
            data = System.getenv("IVORY_HARBOR_USER");
        } else {
            data = null;
        }
        Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
        ivoryHarborLogger.info("Login attempt for user " + data);
    }
}
