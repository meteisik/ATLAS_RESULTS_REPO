import java.util.logging.Logger;

public class CWE117_P10_V1_RuneLanternSafe {

    public static String data;

    public void handleRuneLantern() {
        data = System.getenv("RUNE_LANTERN_USER");
        (new CWE117_P10_V1_RuneLanternSafeSink()).logRuneLantern();
    }
}

class CWE117_P10_V1_RuneLanternSafeSink {
    public void logRuneLantern() {
        String data = CWE117_P10_V1_RuneLanternSafe.data;
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
