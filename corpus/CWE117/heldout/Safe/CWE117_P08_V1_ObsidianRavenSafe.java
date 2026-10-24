import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianRavenSafe {

    public void handleObsidianRaven() {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianRavenSafeSink()).logObsidianRaven(dataArray);
    }
}

class CWE117_P08_V1_ObsidianRavenSafeSink {
    public void logObsidianRaven(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
