import java.util.logging.Logger;

public class CWE117_P05_V2_RuneRavenSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String runeRavenData;

    private void logRuneRaven() {
        String data = runeRavenData;
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleRuneRaven() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_RAVEN_USER");
        } else {
            data = null;
        }
        runeRavenData = data;
        logRuneRaven();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
