import java.util.logging.Logger;

public class CWE117_P06_V2_SilentHarborSafe {

    public void handleSilentHarbor() {
        String data;
        if (5 == 5) {
            data = System.getenv("SILENT_HARBOR_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentHarborSafeSink()).logSilentHarbor(data);
    }
}

class CWE117_P06_V2_SilentHarborSafeSink {
    public void logSilentHarbor(String data) {
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
