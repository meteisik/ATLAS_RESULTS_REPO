import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonHarbor {

    private void logCrimsonHarbor(String data) {
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonHarbor() {
        String data;
        data = System.getenv("CRIMSON_HARBOR_USER");
        logCrimsonHarbor(data);
    }
}
