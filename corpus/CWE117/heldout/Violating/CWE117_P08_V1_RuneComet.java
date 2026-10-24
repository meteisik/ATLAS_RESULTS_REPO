import java.util.logging.Logger;

public class CWE117_P08_V1_RuneComet {

    public void handleRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneCometSink()).logRuneComet(dataArray);
    }
}

class CWE117_P08_V1_RuneCometSink {
    public void logRuneComet(String[] dataArray) {
        String data = dataArray[2];
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + data);
    }
}
