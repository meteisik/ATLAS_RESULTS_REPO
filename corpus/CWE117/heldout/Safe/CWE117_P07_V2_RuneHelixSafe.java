import java.util.logging.Logger;

public class CWE117_P07_V2_RuneHelixSafe {

    public void handleRuneHelix() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_RuneHelixSafeSource()).readRuneHelix();
        } else {
            data = null;
        }
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneHelixSafeSource {
    public String readRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_USER");
        return data;
    }
}
