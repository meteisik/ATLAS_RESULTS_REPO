import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonLanternSafe {

    public void handleCrimsonLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LANTERN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
            crimsonLanternLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
