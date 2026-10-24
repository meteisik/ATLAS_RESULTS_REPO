import java.util.logging.Logger;

public class CWE117_P01_V1_CrimsonHelixSafe {

    public void handleCrimsonHelix() {
        String data;
        data = System.getenv("CRIMSON_HELIX_USER");
        Logger crimsonHelixLogger = Logger.getLogger("crimsonHelix.audit");
        crimsonHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
