import java.util.logging.Logger;

public class CWE117_P07_V2_RuneHelix {

    public void handleRuneHelix() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_RuneHelixSource()).readRuneHelix();
        } else {
            data = null;
        }
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneHelixSource {
    public String readRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_USER");
        return data;
    }
}
