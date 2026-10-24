import java.util.logging.Logger;

public class CWE117_P08_V1_RuneCometSafe {

    public void handleRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneCometSafeSink()).logRuneComet(dataArray);
    }
}

class CWE117_P08_V1_RuneCometSafeSink {
    public void logRuneComet(String[] dataArray) {
        String data = dataArray[2];
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
