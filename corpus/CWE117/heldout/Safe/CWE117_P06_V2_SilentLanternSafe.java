import java.util.logging.Logger;

public class CWE117_P06_V2_SilentLanternSafe {
    private static boolean privateTrue = true;

    public void handleSilentLantern() {
        String data;
        if (privateTrue) {
            data = System.getenv("SILENT_LANTERN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentLanternSafeSink()).logSilentLantern(data);
    }
}

class CWE117_P06_V2_SilentLanternSafeSink {
    public void logSilentLantern(String data) {
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
