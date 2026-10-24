import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxComet {

    private String onyxCometData;

    private void logOnyxComet() {
        String data = onyxCometData;
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + data);
    }

    public void handleOnyxComet() {
        String data;
        if (true) {
            data = System.getenv("ONYX_COMET_USER");
        } else {
            data = null;
        }
        onyxCometData = data;
        logOnyxComet();
    }
}
