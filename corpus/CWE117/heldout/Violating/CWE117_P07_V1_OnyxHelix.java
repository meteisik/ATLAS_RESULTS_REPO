import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxHelix {

    public void handleOnyxHelix() {
        String data;
        data = (new CWE117_P07_V1_OnyxHelixSource()).readOnyxHelix();
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxHelixSource {
    public String readOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        return data;
    }
}
