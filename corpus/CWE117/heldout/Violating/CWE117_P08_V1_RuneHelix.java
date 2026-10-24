import java.util.logging.Logger;

public class CWE117_P08_V1_RuneHelix {

    public void handleRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneHelixSink()).logRuneHelix(dataArray);
    }
}

class CWE117_P08_V1_RuneHelixSink {
    public void logRuneHelix(String[] dataArray) {
        String data = dataArray[2];
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + data);
    }
}
