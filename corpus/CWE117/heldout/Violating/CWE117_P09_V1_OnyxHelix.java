import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxHelix {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxHelixSink()).logOnyxHelix(dataContainer);
    }
}

class CWE117_P09_V1_OnyxHelixSink {
    public void logOnyxHelix(CWE117_P09_V1_OnyxHelix.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + data);
    }
}
