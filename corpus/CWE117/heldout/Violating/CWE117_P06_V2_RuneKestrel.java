import java.util.logging.Logger;

public class CWE117_P06_V2_RuneKestrel {

    public void handleRuneKestrel() {
        String data;
        if (true) {
            data = System.getenv("RUNE_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneKestrelSink()).logRuneKestrel(data);
    }
}

class CWE117_P06_V2_RuneKestrelSink {
    public void logRuneKestrel(String data) {
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + data);
    }
}
