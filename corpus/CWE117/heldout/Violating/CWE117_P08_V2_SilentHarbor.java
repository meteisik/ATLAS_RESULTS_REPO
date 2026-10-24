import java.util.logging.Logger;

public class CWE117_P08_V2_SilentHarbor {
    private static int privateFive = 5;

    public void handleSilentHarbor() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_HARBOR_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentHarborSink()).logSilentHarbor(dataArray);
    }
}

class CWE117_P08_V2_SilentHarborSink {
    public void logSilentHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + data);
    }
}
