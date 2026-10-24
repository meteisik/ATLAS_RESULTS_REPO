import java.util.logging.Logger;

public class CWE117_P06_V2_RuneLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleRuneLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_LOTUS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneLotusSink()).logRuneLotus(data);
    }
}

class CWE117_P06_V2_RuneLotusSink {
    public void logRuneLotus(String data) {
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + data);
    }
}
