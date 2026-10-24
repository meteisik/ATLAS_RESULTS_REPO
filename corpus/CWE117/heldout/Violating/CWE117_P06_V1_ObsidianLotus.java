import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianLotus {

    public void handleObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        (new CWE117_P06_V1_ObsidianLotusSink()).logObsidianLotus(data);
    }
}

class CWE117_P06_V1_ObsidianLotusSink {
    public void logObsidianLotus(String data) {
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }
}
