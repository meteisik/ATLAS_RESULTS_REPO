import java.util.logging.Logger;

public class CWE117_P07_V2_RuneNebula {
    private static int privateFive = 5;

    public void handleRuneNebula() {
        String data;
        if (privateFive == 5) {
            data = (new CWE117_P07_V2_RuneNebulaSource()).readRuneNebula();
        } else {
            data = null;
        }
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneNebulaSource {
    public String readRuneNebula() {
        String data;
        data = System.getenv("RUNE_NEBULA_USER");
        return data;
    }
}
