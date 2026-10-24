import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianLotusSafe {

    public void handleObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        (new CWE117_P06_V1_ObsidianLotusSafeSink()).logObsidianLotus(data);
    }
}

class CWE117_P06_V1_ObsidianLotusSafeSink {
    public void logObsidianLotus(String data) {
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
