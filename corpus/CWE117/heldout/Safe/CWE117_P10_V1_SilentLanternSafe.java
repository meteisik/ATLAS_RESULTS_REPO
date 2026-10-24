import java.util.logging.Logger;

public class CWE117_P10_V1_SilentLanternSafe {

    public static String data;

    public void handleSilentLantern() {
        data = System.getenv("SILENT_LANTERN_USER");
        (new CWE117_P10_V1_SilentLanternSafeSink()).logSilentLantern();
    }
}

class CWE117_P10_V1_SilentLanternSafeSink {
    public void logSilentLantern() {
        String data = CWE117_P10_V1_SilentLanternSafe.data;
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
