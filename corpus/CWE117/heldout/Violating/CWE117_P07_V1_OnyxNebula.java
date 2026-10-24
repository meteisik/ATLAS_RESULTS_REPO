import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxNebula {

    public void handleOnyxNebula() {
        String data;
        data = (new CWE117_P07_V1_OnyxNebulaSource()).readOnyxNebula();
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxNebulaSource {
    public String readOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        return data;
    }
}
