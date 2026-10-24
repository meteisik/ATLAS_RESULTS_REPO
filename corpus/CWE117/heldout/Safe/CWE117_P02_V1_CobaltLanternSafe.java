import java.util.logging.Logger;

public class CWE117_P02_V1_CobaltLanternSafe {

    public void handleCobaltLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_LANTERN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
            cobaltLanternLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
