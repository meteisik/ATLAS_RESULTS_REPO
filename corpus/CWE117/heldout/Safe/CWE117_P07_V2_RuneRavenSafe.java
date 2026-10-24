import java.util.logging.Logger;

public class CWE117_P07_V2_RuneRavenSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleRuneRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_RuneRavenSafeSource()).readRuneRaven();
        } else {
            data = null;
        }
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_RuneRavenSafeSource {
    public String readRuneRaven() {
        String data;
        data = System.getenv("RUNE_RAVEN_USER");
        return data;
    }
}
