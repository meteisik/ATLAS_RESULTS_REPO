import java.util.logging.Logger;

public class CWE117_P08_V1_RuneKestrelSafe {

    public void handleRuneKestrel() {
        String data;
        data = System.getenv("RUNE_KESTREL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneKestrelSafeSink()).logRuneKestrel(dataArray);
    }
}

class CWE117_P08_V1_RuneKestrelSafeSink {
    public void logRuneKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
