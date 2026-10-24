import java.util.logging.Logger;

public class CWE117_P10_V1_SilentHarbor {

    public static String data;

    public void handleSilentHarbor() {
        data = System.getenv("SILENT_HARBOR_USER");
        (new CWE117_P10_V1_SilentHarborSink()).logSilentHarbor();
    }
}

class CWE117_P10_V1_SilentHarborSink {
    public void logSilentHarbor() {
        String data = CWE117_P10_V1_SilentHarbor.data;
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + data);
    }
}
