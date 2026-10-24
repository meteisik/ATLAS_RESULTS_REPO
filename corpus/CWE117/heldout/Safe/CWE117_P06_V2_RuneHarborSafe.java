import java.util.logging.Logger;

public class CWE117_P06_V2_RuneHarborSafe {

    public void handleRuneHarbor() {
        String data;
        while (true) {
            data = System.getenv("RUNE_HARBOR_USER");
            break;
        }
        (new CWE117_P06_V2_RuneHarborSafeSink()).logRuneHarbor(data);
    }
}

class CWE117_P06_V2_RuneHarborSafeSink {
    public void logRuneHarbor(String data) {
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
