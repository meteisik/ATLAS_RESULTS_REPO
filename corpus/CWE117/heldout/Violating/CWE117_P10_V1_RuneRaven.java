import java.util.logging.Logger;

public class CWE117_P10_V1_RuneRaven {

    public static String data;

    public void handleRuneRaven() {
        data = System.getenv("RUNE_RAVEN_USER");
        (new CWE117_P10_V1_RuneRavenSink()).logRuneRaven();
    }
}

class CWE117_P10_V1_RuneRavenSink {
    public void logRuneRaven() {
        String data = CWE117_P10_V1_RuneRaven.data;
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + data);
    }
}
