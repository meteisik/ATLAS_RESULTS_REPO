import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianLantern {

    public void handleObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianLanternSink()).logObsidianLantern(dataArray);
    }
}

class CWE117_P08_V1_ObsidianLanternSink {
    public void logObsidianLantern(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + data);
    }
}
