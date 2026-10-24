import java.util.logging.Logger;

public class CWE117_P08_V1_RuneRaven {

    public void handleRuneRaven() {
        String data;
        data = System.getenv("RUNE_RAVEN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneRavenSink()).logRuneRaven(dataArray);
    }
}

class CWE117_P08_V1_RuneRavenSink {
    public void logRuneRaven(String[] dataArray) {
        String data = dataArray[2];
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + data);
    }
}
