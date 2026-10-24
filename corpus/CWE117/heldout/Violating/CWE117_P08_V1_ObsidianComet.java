import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianComet {

    public void handleObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianCometSink()).logObsidianComet(dataArray);
    }
}

class CWE117_P08_V1_ObsidianCometSink {
    public void logObsidianComet(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + data);
    }
}
