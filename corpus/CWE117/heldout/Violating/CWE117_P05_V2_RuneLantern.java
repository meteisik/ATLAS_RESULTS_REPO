import java.util.logging.Logger;

public class CWE117_P05_V2_RuneLantern {

    private String runeLanternData;

    private void logRuneLantern() {
        String data = runeLanternData;
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + data);
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
}
