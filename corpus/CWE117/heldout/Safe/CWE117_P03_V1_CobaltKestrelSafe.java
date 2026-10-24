import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltKestrelSafe {

    private void logCobaltKestrel(String data) {
        Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
        cobaltKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCobaltKestrel() {
        String data;
        data = System.getenv("COBALT_KESTREL_USER");
        logCobaltKestrel(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
