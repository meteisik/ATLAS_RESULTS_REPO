import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianCometSafe {

    public void handleObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianCometSafeSink()).logObsidianComet(dataArray);
    }
}

class CWE117_P08_V1_ObsidianCometSafeSink {
    public void logObsidianComet(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
