import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianLanternSafe {

    public void handleObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianLanternSafeSink()).logObsidianLantern(dataArray);
    }
}

class CWE117_P08_V1_ObsidianLanternSafeSink {
    public void logObsidianLantern(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
