import java.util.logging.Logger;

public class CWE117_P07_V1_RuneCometSafe {

    public void handleRuneComet() {
        String data;
        data = (new CWE117_P07_V1_RuneCometSafeSource()).readRuneComet();
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_RuneCometSafeSource {
    public String readRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_USER");
        return data;
    }
}
