import java.util.logging.Logger;

public class CWE117_P06_V2_RuneHarbor {

    public void handleRuneHarbor() {
        String data;
        while (true) {
            data = System.getenv("RUNE_HARBOR_USER");
            break;
        }
        (new CWE117_P06_V2_RuneHarborSink()).logRuneHarbor(data);
    }
}

class CWE117_P06_V2_RuneHarborSink {
    public void logRuneHarbor(String data) {
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + data);
    }
}
