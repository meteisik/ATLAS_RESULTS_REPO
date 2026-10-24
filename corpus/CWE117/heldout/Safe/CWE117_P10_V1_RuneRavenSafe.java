import java.util.logging.Logger;

public class CWE117_P10_V1_RuneRavenSafe {

    public static String data;

    public void handleRuneRaven() {
        data = System.getenv("RUNE_RAVEN_USER");
        (new CWE117_P10_V1_RuneRavenSafeSink()).logRuneRaven();
    }
}

class CWE117_P10_V1_RuneRavenSafeSink {
    public void logRuneRaven() {
        String data = CWE117_P10_V1_RuneRavenSafe.data;
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
