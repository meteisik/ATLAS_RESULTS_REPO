import java.util.logging.Logger;

public class CWE117_P10_V1_SilentHarborSafe {

    public static String data;

    public void handleSilentHarbor() {
        data = System.getenv("SILENT_HARBOR_USER");
        (new CWE117_P10_V1_SilentHarborSafeSink()).logSilentHarbor();
    }
}

class CWE117_P10_V1_SilentHarborSafeSink {
    public void logSilentHarbor() {
        String data = CWE117_P10_V1_SilentHarborSafe.data;
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
