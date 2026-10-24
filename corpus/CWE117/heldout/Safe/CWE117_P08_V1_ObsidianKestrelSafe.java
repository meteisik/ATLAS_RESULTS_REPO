import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianKestrelSafe {

    public void handleObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianKestrelSafeSink()).logObsidianKestrel(dataArray);
    }
}

class CWE117_P08_V1_ObsidianKestrelSafeSink {
    public void logObsidianKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
