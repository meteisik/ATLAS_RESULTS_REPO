import java.util.logging.Logger;

public class CWE117_P07_V2_RuneLanternSafe {
    private static boolean privateTrue = true;

    public void handleRuneLantern() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_RuneLanternSafeSource()).readRuneLantern();
        } else {
            data = null;
        }
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneLanternSafeSource {
    public String readRuneLantern() {
        String data;
        data = System.getenv("RUNE_LANTERN_USER");
        return data;
    }
}
