import java.util.logging.Logger;

public class CWE117_P07_V2_RuneLantern {
    private static boolean privateTrue = true;

    public void handleRuneLantern() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_RuneLanternSource()).readRuneLantern();
        } else {
            data = null;
        }
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneLanternSource {
    public String readRuneLantern() {
        String data;
        data = System.getenv("RUNE_LANTERN_USER");
        return data;
    }
}
