import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxRaven {

    public void handleOnyxRaven() {
        String data;
        data = (new CWE117_P07_V1_OnyxRavenSource()).readOnyxRaven();
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxRavenSource {
    public String readOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_USER");
        return data;
    }
}
