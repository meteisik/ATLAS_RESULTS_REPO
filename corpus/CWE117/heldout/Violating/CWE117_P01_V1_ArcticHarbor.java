import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticHarbor {

    public void handleArcticHarbor() {
        String data;
        data = System.getenv("ARCTIC_HARBOR_USER");
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + data);
    }
}
