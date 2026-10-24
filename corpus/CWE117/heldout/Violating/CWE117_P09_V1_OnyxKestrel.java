import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxKestrel {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxKestrelSink()).logOnyxKestrel(dataContainer);
    }
}

class CWE117_P09_V1_OnyxKestrelSink {
    public void logOnyxKestrel(CWE117_P09_V1_OnyxKestrel.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + data);
    }
}
