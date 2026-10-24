import java.util.logging.Logger;

public class CWE117_P10_V1_RuneKestrelSafe {

    public static String data;

    public void handleRuneKestrel() {
        data = System.getenv("RUNE_KESTREL_USER");
        (new CWE117_P10_V1_RuneKestrelSafeSink()).logRuneKestrel();
    }
}

class CWE117_P10_V1_RuneKestrelSafeSink {
    public void logRuneKestrel() {
        String data = CWE117_P10_V1_RuneKestrelSafe.data;
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
