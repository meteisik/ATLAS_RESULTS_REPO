import java.util.logging.Logger;

public class CWE117_P10_V1_SilentKestrel {

    public static String data;

    public void handleSilentKestrel() {
        data = System.getenv("SILENT_KESTREL_USER");
        (new CWE117_P10_V1_SilentKestrelSink()).logSilentKestrel();
    }
}

class CWE117_P10_V1_SilentKestrelSink {
    public void logSilentKestrel() {
        String data = CWE117_P10_V1_SilentKestrel.data;
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + data);
    }
}
