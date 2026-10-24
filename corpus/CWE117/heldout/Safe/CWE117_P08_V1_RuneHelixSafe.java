import java.util.logging.Logger;

public class CWE117_P08_V1_RuneHelixSafe {

    public void handleRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneHelixSafeSink()).logRuneHelix(dataArray);
    }
}

class CWE117_P08_V1_RuneHelixSafeSink {
    public void logRuneHelix(String[] dataArray) {
        String data = dataArray[2];
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
