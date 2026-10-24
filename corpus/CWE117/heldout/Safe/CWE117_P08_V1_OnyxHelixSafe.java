import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxHelixSafe {

    public void handleOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxHelixSafeSink()).logOnyxHelix(dataArray);
    }
}

class CWE117_P08_V1_OnyxHelixSafeSink {
    public void logOnyxHelix(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
