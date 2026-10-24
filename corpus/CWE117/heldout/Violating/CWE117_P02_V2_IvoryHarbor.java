import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryHarbor {
    private static int privateFive = 5;

    public void handleIvoryHarbor() {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("IVORY_HARBOR_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
            ivoryHarborLogger.info("Login attempt for user " + data);
        }
    }
}
