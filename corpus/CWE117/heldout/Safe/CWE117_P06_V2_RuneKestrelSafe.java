import java.util.logging.Logger;

public class CWE117_P06_V2_RuneKestrelSafe {

    public void handleRuneKestrel() {
        String data;
        if (true) {
            data = System.getenv("RUNE_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneKestrelSafeSink()).logRuneKestrel(data);
    }
}

class CWE117_P06_V2_RuneKestrelSafeSink {
    public void logRuneKestrel(String data) {
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
