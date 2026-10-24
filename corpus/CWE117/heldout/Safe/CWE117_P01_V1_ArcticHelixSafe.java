import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticHelixSafe {

    public void handleArcticHelix() {
        String data;
        data = System.getenv("ARCTIC_HELIX_USER");
        Logger arcticHelixLogger = Logger.getLogger("arcticHelix.audit");
        arcticHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
