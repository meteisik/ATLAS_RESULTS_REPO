import java.util.logging.Logger;

public class CWE117_P08_V1_RuneLotusSafe {

    public void handleRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneLotusSafeSink()).logRuneLotus(dataArray);
    }
}

class CWE117_P08_V1_RuneLotusSafeSink {
    public void logRuneLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
