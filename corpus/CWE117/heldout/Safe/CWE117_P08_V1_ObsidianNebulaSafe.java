import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianNebulaSafe {

    public void handleObsidianNebula() {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianNebulaSafeSink()).logObsidianNebula(dataArray);
    }
}

class CWE117_P08_V1_ObsidianNebulaSafeSink {
    public void logObsidianNebula(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
