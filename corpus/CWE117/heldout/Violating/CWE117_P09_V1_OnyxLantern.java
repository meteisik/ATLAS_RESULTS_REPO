import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxLantern {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxLantern() {
        String data;
        data = System.getenv("ONYX_LANTERN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxLanternSink()).logOnyxLantern(dataContainer);
    }
}

class CWE117_P09_V1_OnyxLanternSink {
    public void logOnyxLantern(CWE117_P09_V1_OnyxLantern.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + data);
    }
}
