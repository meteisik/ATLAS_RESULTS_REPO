import java.util.logging.Logger;

public class CWE117_P07_V2_RuneKestrelSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleRuneKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_RuneKestrelSafeSource()).readRuneKestrel();
        } else {
            data = null;
        }
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneKestrelSafeSource {
    public String readRuneKestrel() {
        String data;
        data = System.getenv("RUNE_KESTREL_USER");
        return data;
    }
}
