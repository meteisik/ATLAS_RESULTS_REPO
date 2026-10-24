import java.util.logging.Logger;

public class CWE117_P07_V2_SilentLanternSafe {
    private static int privateFive = 5;

    public void handleSilentLantern() {
        String data;
        if (privateFive == 5) {
            data = (new CWE117_P07_V2_SilentLanternSafeSource()).readSilentLantern();
        } else {
            data = null;
        }
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SilentLanternSafeSource {
    public String readSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_USER");
        return data;
    }
}
