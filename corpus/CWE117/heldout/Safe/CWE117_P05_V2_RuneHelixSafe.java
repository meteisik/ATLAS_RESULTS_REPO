import java.util.logging.Logger;

public class CWE117_P05_V2_RuneHelixSafe {

    private String runeHelixData;

    private void logRuneHelix() {
        String data = runeHelixData;
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleRuneHelix() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_HELIX_USER");
            break;
        default:
            data = null;
            break;
        }
        runeHelixData = data;
        logRuneHelix();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
