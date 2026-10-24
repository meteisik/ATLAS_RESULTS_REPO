import java.util.logging.Logger;

public class CWE117_P05_V2_RuneLotusSafe {

    private String runeLotusData;

    private void logRuneLotus() {
        String data = runeLotusData;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
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

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
