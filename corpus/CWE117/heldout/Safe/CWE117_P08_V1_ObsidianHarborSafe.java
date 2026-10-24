import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianHarborSafe {

    public void handleObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianHarborSafeSink()).logObsidianHarbor(dataArray);
    }
}

class CWE117_P08_V1_ObsidianHarborSafeSink {
    public void logObsidianHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
