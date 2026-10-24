import java.util.logging.Logger;

public class CWE117_P06_V2_SilentKestrelSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleSilentKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentKestrelSafeSink()).logSilentKestrel(data);
    }
}

class CWE117_P06_V2_SilentKestrelSafeSink {
    public void logSilentKestrel(String data) {
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
