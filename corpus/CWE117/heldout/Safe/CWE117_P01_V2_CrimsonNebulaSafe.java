import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonNebulaSafe {
    private static boolean privateTrue = true;

    public void handleCrimsonNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("CRIMSON_NEBULA_USER");
        } else {
            data = null;
        }
        Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
        crimsonNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
