import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonLanternSafe {

    public void handleCrimsonLantern() {
        String data;
        if (5 == 5) {
            data = System.getenv("CRIMSON_LANTERN_USER");
        } else {
            data = null;
        }
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
