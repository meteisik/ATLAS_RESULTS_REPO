import java.util.logging.Logger;

public class CWE117_P06_V2_SilentKestrel {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleSilentKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentKestrelSink()).logSilentKestrel(data);
    }
}

class CWE117_P06_V2_SilentKestrelSink {
    public void logSilentKestrel(String data) {
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + data);
    }
}
