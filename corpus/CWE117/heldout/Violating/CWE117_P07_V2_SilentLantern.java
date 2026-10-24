import java.util.logging.Logger;

public class CWE117_P07_V2_SilentLantern {
    private static int privateFive = 5;

    public void handleSilentLantern() {
        String data;
        if (privateFive == 5) {
            data = (new CWE117_P07_V2_SilentLanternSource()).readSilentLantern();
        } else {
            data = null;
        }
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentLanternSource {
    public String readSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_USER");
        return data;
    }
}
