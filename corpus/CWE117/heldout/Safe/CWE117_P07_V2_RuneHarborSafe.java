import java.util.logging.Logger;

public class CWE117_P07_V2_RuneHarborSafe {

    public void handleRuneHarbor() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_RuneHarborSafeSource()).readRuneHarbor();
        } else {
            data = null;
        }
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneHarborSafeSource {
    public String readRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_USER");
        return data;
    }
}
