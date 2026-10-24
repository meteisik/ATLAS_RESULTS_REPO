import java.util.logging.Logger;

public class CWE117_P10_V1_RuneHelix {

    public static String data;

    public void handleRuneHelix() {
        data = System.getenv("RUNE_HELIX_USER");
        (new CWE117_P10_V1_RuneHelixSink()).logRuneHelix();
    }
}

class CWE117_P10_V1_RuneHelixSink {
    public void logRuneHelix() {
        String data = CWE117_P10_V1_RuneHelix.data;
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + data);
    }
}
