import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonKestrelSafe {

    public void handleCrimsonKestrel() {
        String data;
        if (true) {
            data = System.getenv("CRIMSON_KESTREL_USER");
        } else {
            data = null;
        }
        Logger crimsonKestrelLogger = Logger.getLogger("crimsonKestrel.audit");
        crimsonKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
