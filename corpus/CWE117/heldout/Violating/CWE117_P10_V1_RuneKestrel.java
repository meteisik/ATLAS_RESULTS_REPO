import java.util.logging.Logger;

public class CWE117_P10_V1_RuneKestrel {

    public static String data;

    public void handleRuneKestrel() {
        data = System.getenv("RUNE_KESTREL_USER");
        (new CWE117_P10_V1_RuneKestrelSink()).logRuneKestrel();
    }
}

class CWE117_P10_V1_RuneKestrelSink {
    public void logRuneKestrel() {
        String data = CWE117_P10_V1_RuneKestrel.data;
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + data);
    }
}
