import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonHarbor {

    public void handleCrimsonHarbor() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_HARBOR_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
            crimsonHarborLogger.info("Login attempt for user " + data);
        }
    }
}
