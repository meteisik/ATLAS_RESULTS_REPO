import java.util.logging.Logger;

public class CWE117_P07_V2_SilentHarborSafe {
    private static boolean privateTrue = true;

    public void handleSilentHarbor() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_SilentHarborSafeSource()).readSilentHarbor();
        } else {
            data = null;
        }
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SilentHarborSafeSource {
    public String readSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_USER");
        return data;
    }
}
