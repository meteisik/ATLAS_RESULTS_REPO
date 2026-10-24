import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltKestrelSafe {

    public void handleCobaltKestrel() {
        String data;
        data = System.getenv("COBALT_KESTREL_USER");
        Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
        cobaltKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
