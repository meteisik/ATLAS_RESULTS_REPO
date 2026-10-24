import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianLotusSafe {

    public void handleObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianLotusSafeSink()).logObsidianLotus(dataArray);
    }
}

class CWE117_P08_V1_ObsidianLotusSafeSink {
    public void logObsidianLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
