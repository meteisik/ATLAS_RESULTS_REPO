import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxHarbor {

    public void handleOnyxHarbor() {
        String data;
        data = (new CWE117_P07_V1_OnyxHarborSource()).readOnyxHarbor();
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxHarborSource {
    public String readOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_USER");
        return data;
    }
}
