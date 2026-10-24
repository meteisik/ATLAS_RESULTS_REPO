import java.util.logging.Logger;

public class CWE117_P06_V2_RuneHelixSafe {

    public void handleRuneHelix() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_HELIX_USER");
        }
        (new CWE117_P06_V2_RuneHelixSafeSink()).logRuneHelix(data);
    }
}

class CWE117_P06_V2_RuneHelixSafeSink {
    public void logRuneHelix(String data) {
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
