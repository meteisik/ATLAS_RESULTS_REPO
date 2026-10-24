import java.util.logging.Logger;

public class CWE117_P10_V1_RuneLotusSafe {

    public static String data;

    public void handleRuneLotus() {
        data = System.getenv("RUNE_LOTUS_USER");
        (new CWE117_P10_V1_RuneLotusSafeSink()).logRuneLotus();
    }
}

class CWE117_P10_V1_RuneLotusSafeSink {
    public void logRuneLotus() {
        String data = CWE117_P10_V1_RuneLotusSafe.data;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
