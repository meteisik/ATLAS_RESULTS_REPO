import java.util.logging.Logger;

public class CWE117_P05_V2_RuneLanternSafe {

    private String runeLanternData;

    private void logRuneLantern() {
        String data = runeLanternData;
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleRuneLantern() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_LANTERN_USER");
        }
        runeLanternData = data;
        logRuneLantern();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
