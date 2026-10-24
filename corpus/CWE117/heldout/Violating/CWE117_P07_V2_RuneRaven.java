import java.util.logging.Logger;

public class CWE117_P07_V2_RuneRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void handleRuneRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_RuneRavenSource()).readRuneRaven();
        } else {
            data = null;
        }
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneRavenSource {
    public String readRuneRaven() {
        String data;
        data = System.getenv("RUNE_RAVEN_USER");
        return data;
    }
}
