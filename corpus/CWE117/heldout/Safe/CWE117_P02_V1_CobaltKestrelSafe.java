import java.util.logging.Logger;

public class CWE117_P02_V1_CobaltKestrelSafe {

    public void handleCobaltKestrel() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_KESTREL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
            cobaltKestrelLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
