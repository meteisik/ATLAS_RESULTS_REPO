import java.util.logging.Logger;

public class CWE117_P07_V1_RuneComet {

    public void handleRuneComet() {
        String data;
        data = (new CWE117_P07_V1_RuneCometSource()).readRuneComet();
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_RuneCometSource {
    public String readRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_USER");
        return data;
    }
}
