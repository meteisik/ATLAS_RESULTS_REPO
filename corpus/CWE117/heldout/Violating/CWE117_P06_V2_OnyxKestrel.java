import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxKestrel {
    private static int privateFive = 5;

    public void handleOnyxKestrel() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxKestrelSink()).logOnyxKestrel(data);
    }
}

class CWE117_P06_V2_OnyxKestrelSink {
    public void logOnyxKestrel(String data) {
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + data);
    }
}
