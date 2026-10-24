import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxHelix {

    public void handleOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxHelixSink()).logOnyxHelix(dataArray);
    }
}

class CWE117_P08_V1_OnyxHelixSink {
    public void logOnyxHelix(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + data);
    }
}
