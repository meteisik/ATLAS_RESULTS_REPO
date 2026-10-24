import java.util.logging.Logger;

public class CWE117_P10_V1_SilentLantern {

    public static String data;

    public void handleSilentLantern() {
        data = System.getenv("SILENT_LANTERN_USER");
        (new CWE117_P10_V1_SilentLanternSink()).logSilentLantern();
    }
}

class CWE117_P10_V1_SilentLanternSink {
    public void logSilentLantern() {
        String data = CWE117_P10_V1_SilentLantern.data;
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + data);
    }
}
