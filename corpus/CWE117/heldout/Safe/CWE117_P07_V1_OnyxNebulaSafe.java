import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxNebulaSafe {

    public void handleOnyxNebula() {
        String data;
        data = (new CWE117_P07_V1_OnyxNebulaSafeSource()).readOnyxNebula();
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxNebulaSafeSource {
    public String readOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        return data;
    }
}
