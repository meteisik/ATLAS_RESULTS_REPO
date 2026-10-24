import java.util.logging.Logger;

public class CWE117_P10_V1_RuneNebula {

    public static String data;

    public void handleRuneNebula() {
        data = System.getenv("RUNE_NEBULA_USER");
        (new CWE117_P10_V1_RuneNebulaSink()).logRuneNebula();
    }
}

class CWE117_P10_V1_RuneNebulaSink {
    public void logRuneNebula() {
        String data = CWE117_P10_V1_RuneNebula.data;
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + data);
    }
}
