import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianLotus {

    public void handleObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianLotusSink()).logObsidianLotus(dataArray);
    }
}

class CWE117_P08_V1_ObsidianLotusSink {
    public void logObsidianLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }
}
