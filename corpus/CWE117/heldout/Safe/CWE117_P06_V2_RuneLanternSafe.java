import java.util.logging.Logger;

public class CWE117_P06_V2_RuneLanternSafe {

    public void handleRuneLantern() {
        String data;
        if (5 == 5) {
            data = System.getenv("RUNE_LANTERN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneLanternSafeSink()).logRuneLantern(data);
    }
}

class CWE117_P06_V2_RuneLanternSafeSink {
    public void logRuneLantern(String data) {
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
