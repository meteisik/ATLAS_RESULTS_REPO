import java.util.logging.Logger;

public class CWE117_P05_V2_RuneKestrel {

    private String runeKestrelData;

    private void logRuneKestrel() {
        String data = runeKestrelData;
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleRuneKestrel() {
        String data;
        while (true) {
            data = System.getenv("RUNE_KESTREL_USER");
            break;
        }
        runeKestrelData = data;
        logRuneKestrel();
    }
}
