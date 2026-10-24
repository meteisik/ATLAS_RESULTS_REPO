import java.util.logging.Logger;

public class CWE117_P06_V2_SilentHarbor {

    public void handleSilentHarbor() {
        String data;
        if (5 == 5) {
            data = System.getenv("SILENT_HARBOR_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentHarborSink()).logSilentHarbor(data);
    }
}

class CWE117_P06_V2_SilentHarborSink {
    public void logSilentHarbor(String data) {
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + data);
    }
}
