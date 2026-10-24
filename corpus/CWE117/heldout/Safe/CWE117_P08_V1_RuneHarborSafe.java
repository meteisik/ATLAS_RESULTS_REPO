import java.util.logging.Logger;

public class CWE117_P08_V1_RuneHarborSafe {

    public void handleRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneHarborSafeSink()).logRuneHarbor(dataArray);
    }
}

class CWE117_P08_V1_RuneHarborSafeSink {
    public void logRuneHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
