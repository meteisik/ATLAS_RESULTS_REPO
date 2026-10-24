import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonRavenSafe {

    public void handleCrimsonRaven() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_RAVEN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
            crimsonRavenLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
