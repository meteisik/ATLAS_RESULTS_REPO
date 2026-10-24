import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltLanternSafe {

    public void handleCobaltLantern() {
        String data;
        data = System.getenv("COBALT_LANTERN_USER");
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
