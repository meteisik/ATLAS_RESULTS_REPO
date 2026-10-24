import java.util.logging.Logger;

public class CWE117_P08_V1_RuneRavenSafe {

    public void handleRuneRaven() {
        String data;
        data = System.getenv("RUNE_RAVEN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneRavenSafeSink()).logRuneRaven(dataArray);
    }
}

class CWE117_P08_V1_RuneRavenSafeSink {
    public void logRuneRaven(String[] dataArray) {
        String data = dataArray[2];
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
