import java.util.logging.Logger;

public class CWE117_P06_V2_SilentLantern {
    private static boolean privateTrue = true;

    public void handleSilentLantern() {
        String data;
        if (privateTrue) {
            data = System.getenv("SILENT_LANTERN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentLanternSink()).logSilentLantern(data);
    }
}

class CWE117_P06_V2_SilentLanternSink {
    public void logSilentLantern(String data) {
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + data);
    }
}
