import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianKestrel {

    public void handleObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianKestrelSink()).logObsidianKestrel(dataArray);
    }
}

class CWE117_P08_V1_ObsidianKestrelSink {
    public void logObsidianKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + data);
    }
}
