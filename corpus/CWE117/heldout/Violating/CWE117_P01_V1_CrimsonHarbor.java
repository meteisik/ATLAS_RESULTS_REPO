import java.util.logging.Logger;

public class CWE117_P01_V1_CrimsonHarbor {

    public void handleCrimsonHarbor() {
        String data;
        data = System.getenv("CRIMSON_HARBOR_USER");
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + data);
    }
}
