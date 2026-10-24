import java.util.logging.Logger;

public class CWE117_P05_V2_RuneLotus {

    private String runeLotusData;

    private void logRuneLotus() {
        String data = runeLotusData;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + data);
    }

    public void handleRuneLotus() {
        String data;
        if (true) {
            data = System.getenv("RUNE_LOTUS_USER");
        } else {
            data = null;
        }
        runeLotusData = data;
        logRuneLotus();
    }
}
