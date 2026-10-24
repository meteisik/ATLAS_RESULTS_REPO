import java.util.logging.Logger;

public class CWE117_P10_V1_RuneLantern {

    public static String data;

    public void handleRuneLantern() {
        data = System.getenv("RUNE_LANTERN_USER");
        (new CWE117_P10_V1_RuneLanternSink()).logRuneLantern();
    }
}

class CWE117_P10_V1_RuneLanternSink {
    public void logRuneLantern() {
        String data = CWE117_P10_V1_RuneLantern.data;
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + data);
    }
}
