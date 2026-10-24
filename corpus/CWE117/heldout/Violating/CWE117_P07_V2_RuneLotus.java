import java.util.logging.Logger;

public class CWE117_P07_V2_RuneLotus {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleRuneLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_RuneLotusSource()).readRuneLotus();
        } else {
            data = null;
        }
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_RuneLotusSource {
    public String readRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_USER");
        return data;
    }
}
