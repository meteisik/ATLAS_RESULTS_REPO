import java.util.logging.Logger;

public class CWE117_P10_V1_RuneNebulaSafe {

    public static String data;

    public void handleRuneNebula() {
        data = System.getenv("RUNE_NEBULA_USER");
        (new CWE117_P10_V1_RuneNebulaSafeSink()).logRuneNebula();
    }
}

class CWE117_P10_V1_RuneNebulaSafeSink {
    public void logRuneNebula() {
        String data = CWE117_P10_V1_RuneNebulaSafe.data;
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
