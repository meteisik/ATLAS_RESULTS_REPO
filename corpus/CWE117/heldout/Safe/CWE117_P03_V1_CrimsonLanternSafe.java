import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonLanternSafe {

    private void logCrimsonLantern(String data) {
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonLantern() {
        String data;
        data = System.getenv("CRIMSON_LANTERN_USER");
        logCrimsonLantern(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
