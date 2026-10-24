import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonKestrelSafe {

    private void logCrimsonKestrel(String data) {
        Logger crimsonKestrelLogger = Logger.getLogger("crimsonKestrel.audit");
        crimsonKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonKestrel() {
        String data;
        data = System.getenv("CRIMSON_KESTREL_USER");
        logCrimsonKestrel(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
