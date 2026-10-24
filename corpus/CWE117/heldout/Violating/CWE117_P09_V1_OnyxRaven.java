import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxRaven {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxRavenSink()).logOnyxRaven(dataContainer);
    }
}

class CWE117_P09_V1_OnyxRavenSink {
    public void logOnyxRaven(CWE117_P09_V1_OnyxRaven.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + data);
    }
}
