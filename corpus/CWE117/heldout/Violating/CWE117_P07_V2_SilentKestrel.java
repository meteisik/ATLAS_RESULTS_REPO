import java.util.logging.Logger;

public class CWE117_P07_V2_SilentKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleSilentKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_SilentKestrelSource()).readSilentKestrel();
        } else {
            data = null;
        }
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentKestrelSource {
    public String readSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_USER");
        return data;
    }
}
