import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxComet {

    private String readOnyxComet() {
        String data;
        while (true) {
            data = System.getenv("ONYX_COMET_USER");
            break;
        }
        return data;
    }

    public void handleOnyxComet() {
        String data = readOnyxComet();
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + data);
    }
}
