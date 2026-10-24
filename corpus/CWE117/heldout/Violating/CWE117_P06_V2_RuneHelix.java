import java.util.logging.Logger;

public class CWE117_P06_V2_RuneHelix {

    public void handleRuneHelix() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_HELIX_USER");
        }
        (new CWE117_P06_V2_RuneHelixSink()).logRuneHelix(data);
    }
}

class CWE117_P06_V2_RuneHelixSink {
    public void logRuneHelix(String data) {
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + data);
    }
}
