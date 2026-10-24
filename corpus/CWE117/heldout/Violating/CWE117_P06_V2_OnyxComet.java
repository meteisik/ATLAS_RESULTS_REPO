import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxComet {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleOnyxComet() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_COMET_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxCometSink()).logOnyxComet(data);
    }
}

class CWE117_P06_V2_OnyxCometSink {
    public void logOnyxComet(String data) {
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + data);
    }
}
