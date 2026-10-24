import java.util.logging.Logger;

public class CWE117_P06_V2_RuneLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleRuneLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_LOTUS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneLotusSafeSink()).logRuneLotus(data);
    }
}

class CWE117_P06_V2_RuneLotusSafeSink {
    public void logRuneLotus(String data) {
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
