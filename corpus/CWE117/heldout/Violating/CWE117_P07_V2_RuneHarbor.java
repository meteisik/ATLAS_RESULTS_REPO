import java.util.logging.Logger;

public class CWE117_P07_V2_RuneHarbor {

    public void handleRuneHarbor() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_RuneHarborSource()).readRuneHarbor();
        } else {
            data = null;
        }
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneHarborSource {
    public String readRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_USER");
        return data;
    }
}
