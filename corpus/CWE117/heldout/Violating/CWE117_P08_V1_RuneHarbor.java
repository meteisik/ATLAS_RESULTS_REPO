import java.util.logging.Logger;

public class CWE117_P08_V1_RuneHarbor {

    public void handleRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneHarborSink()).logRuneHarbor(dataArray);
    }
}

class CWE117_P08_V1_RuneHarborSink {
    public void logRuneHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + data);
    }
}
