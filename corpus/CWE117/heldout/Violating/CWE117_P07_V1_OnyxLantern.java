import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxLantern {

    public void handleOnyxLantern() {
        String data;
        data = (new CWE117_P07_V1_OnyxLanternSource()).readOnyxLantern();
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxLanternSource {
    public String readOnyxLantern() {
        String data;
        data = System.getenv("ONYX_LANTERN_USER");
        return data;
    }
}
