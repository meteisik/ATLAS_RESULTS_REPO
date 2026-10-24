import java.util.logging.Logger;

public class CWE117_P07_V2_SilentHarbor {
    private static boolean privateTrue = true;

    public void handleSilentHarbor() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_SilentHarborSource()).readSilentHarbor();
        } else {
            data = null;
        }
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentHarborSource {
    public String readSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_USER");
        return data;
    }
}
