import java.util.logging.Logger;

public class CWE117_P07_V2_RuneLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleRuneLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_RuneLotusSafeSource()).readRuneLotus();
        } else {
            data = null;
        }
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneLotusSafeSource {
    public String readRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_USER");
        return data;
    }
}
