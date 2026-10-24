import java.util.logging.Logger;

public class CWE117_P10_V1_RuneHelixSafe {

    public static String data;

    public void handleRuneHelix() {
        data = System.getenv("RUNE_HELIX_USER");
        (new CWE117_P10_V1_RuneHelixSafeSink()).logRuneHelix();
    }
}

class CWE117_P10_V1_RuneHelixSafeSink {
    public void logRuneHelix() {
        String data = CWE117_P10_V1_RuneHelixSafe.data;
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
