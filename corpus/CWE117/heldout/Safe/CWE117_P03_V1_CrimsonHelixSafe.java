import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonHelixSafe {

    private void logCrimsonHelix(String data) {
        Logger crimsonHelixLogger = Logger.getLogger("crimsonHelix.audit");
        crimsonHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonHelix() {
        String data;
        data = System.getenv("CRIMSON_HELIX_USER");
        logCrimsonHelix(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
