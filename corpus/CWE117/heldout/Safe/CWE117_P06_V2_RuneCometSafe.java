import java.util.logging.Logger;

public class CWE117_P06_V2_RuneCometSafe {

    public void handleRuneComet() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_COMET_USER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE117_P06_V2_RuneCometSafeSink()).logRuneComet(data);
    }
}

class CWE117_P06_V2_RuneCometSafeSink {
    public void logRuneComet(String data) {
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
