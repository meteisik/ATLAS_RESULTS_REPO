import java.util.logging.Logger;

public class CWE117_P06_V2_RuneNebula {
    private static boolean privateTrue = true;

    public void handleRuneNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("RUNE_NEBULA_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneNebulaSink()).logRuneNebula(data);
    }
}

class CWE117_P06_V2_RuneNebulaSink {
    public void logRuneNebula(String data) {
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + data);
    }
}
