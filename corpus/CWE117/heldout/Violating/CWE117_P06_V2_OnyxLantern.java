import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxLantern {
    private static boolean privateReturnsTrue() { return true; }

    public void handleOnyxLantern() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_LANTERN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxLanternSink()).logOnyxLantern(data);
    }
}

class CWE117_P06_V2_OnyxLanternSink {
    public void logOnyxLantern(String data) {
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + data);
    }
}
