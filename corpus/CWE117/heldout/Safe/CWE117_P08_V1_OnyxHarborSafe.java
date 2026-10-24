import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxHarborSafe {

    public void handleOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxHarborSafeSink()).logOnyxHarbor(dataArray);
    }
}

class CWE117_P08_V1_OnyxHarborSafeSink {
    public void logOnyxHarbor(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
