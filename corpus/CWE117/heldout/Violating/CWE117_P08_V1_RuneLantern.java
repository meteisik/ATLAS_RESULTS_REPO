import java.util.logging.Logger;

public class CWE117_P08_V1_RuneLantern {

    public void handleRuneLantern() {
        String data;
        data = System.getenv("RUNE_LANTERN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneLanternSink()).logRuneLantern(dataArray);
    }
}

class CWE117_P08_V1_RuneLanternSink {
    public void logRuneLantern(String[] dataArray) {
        String data = dataArray[2];
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + data);
    }
}
