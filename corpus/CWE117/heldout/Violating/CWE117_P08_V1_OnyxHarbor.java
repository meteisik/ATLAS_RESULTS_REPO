import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxHarbor {

    public void handleOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxHarborSink()).logOnyxHarbor(dataArray);
    }
}

class CWE117_P08_V1_OnyxHarborSink {
    public void logOnyxHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + data);
    }
}
