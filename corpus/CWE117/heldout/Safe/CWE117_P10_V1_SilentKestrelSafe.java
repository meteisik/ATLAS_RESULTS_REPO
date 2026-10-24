import java.util.logging.Logger;

public class CWE117_P10_V1_SilentKestrelSafe {

    public static String data;

    public void handleSilentKestrel() {
        data = System.getenv("SILENT_KESTREL_USER");
        (new CWE117_P10_V1_SilentKestrelSafeSink()).logSilentKestrel();
    }
}

class CWE117_P10_V1_SilentKestrelSafeSink {
    public void logSilentKestrel() {
        String data = CWE117_P10_V1_SilentKestrelSafe.data;
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
