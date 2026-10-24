import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianHelix {

    public void handleObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianHelixSink()).logObsidianHelix(dataArray);
    }
}

class CWE117_P08_V1_ObsidianHelixSink {
    public void logObsidianHelix(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
    }
}
