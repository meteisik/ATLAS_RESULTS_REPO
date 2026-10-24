import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxKestrel {

    public void handleOnyxKestrel() {
        String data;
        data = (new CWE117_P07_V1_OnyxKestrelSource()).readOnyxKestrel();
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxKestrelSource {
    public String readOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        return data;
    }
}
