import java.util.logging.Logger;

public class CWE117_P05_V2_RuneNebula {

    private String runeNebulaData;

    private void logRuneNebula() {
        String data = runeNebulaData;
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + data);
    }

    public void handleRuneNebula() {
        String data;
        if (5 == 5) {
            data = System.getenv("RUNE_NEBULA_USER");
        } else {
            data = null;
        }
        runeNebulaData = data;
        logRuneNebula();
    }
}
