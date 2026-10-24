import java.util.logging.Logger;

public class CWE117_P06_V2_RuneNebulaSafe {
    private static boolean privateTrue = true;

    public void handleRuneNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("RUNE_NEBULA_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneNebulaSafeSink()).logRuneNebula(data);
    }
}

class CWE117_P06_V2_RuneNebulaSafeSink {
    public void logRuneNebula(String data) {
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
