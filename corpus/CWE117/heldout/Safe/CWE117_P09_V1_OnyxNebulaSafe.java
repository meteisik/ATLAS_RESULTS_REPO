import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxNebulaSafe {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxNebulaSafeSink()).logOnyxNebula(dataContainer);
    }
}

class CWE117_P09_V1_OnyxNebulaSafeSink {
    public void logOnyxNebula(CWE117_P09_V1_OnyxNebulaSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
