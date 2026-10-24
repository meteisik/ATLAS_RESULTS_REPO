import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxComet {

    public void handleOnyxComet() {
        String data;
        data = (new CWE117_P07_V1_OnyxCometSource()).readOnyxComet();
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxCometSource {
    public String readOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_USER");
        return data;
    }
}
