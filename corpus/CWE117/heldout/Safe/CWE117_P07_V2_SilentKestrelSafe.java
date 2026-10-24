import java.util.logging.Logger;

public class CWE117_P07_V2_SilentKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleSilentKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_SilentKestrelSafeSource()).readSilentKestrel();
        } else {
            data = null;
        }
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SilentKestrelSafeSource {
    public String readSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_USER");
        return data;
    }
}
