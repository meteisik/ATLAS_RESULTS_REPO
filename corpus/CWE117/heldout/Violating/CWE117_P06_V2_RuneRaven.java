import java.util.logging.Logger;

public class CWE117_P06_V2_RuneRaven {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleRuneRaven() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneRavenSink()).logRuneRaven(data);
    }
}

class CWE117_P06_V2_RuneRavenSink {
    public void logRuneRaven(String data) {
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + data);
    }
}
