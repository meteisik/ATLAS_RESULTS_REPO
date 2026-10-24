import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianHarbor {

    public void handleObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianHarborSink()).logObsidianHarbor(dataArray);
    }
}

class CWE117_P08_V1_ObsidianHarborSink {
    public void logObsidianHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }
}
