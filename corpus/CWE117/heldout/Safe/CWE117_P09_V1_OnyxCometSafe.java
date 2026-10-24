import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxCometSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxCometSafeSink()).logOnyxComet(dataContainer);
    }
}

class CWE117_P09_V1_OnyxCometSafeSink {
    public void logOnyxComet(CWE117_P09_V1_OnyxCometSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
