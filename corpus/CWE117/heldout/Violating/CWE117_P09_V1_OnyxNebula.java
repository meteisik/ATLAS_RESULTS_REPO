import java.util.logging.Logger;

public class CWE117_P09_V1_OnyxNebula {

    static class Container {
        public String containerOne;
    }

    public void handleOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_OnyxNebulaSink()).logOnyxNebula(dataContainer);
    }
}

class CWE117_P09_V1_OnyxNebulaSink {
    public void logOnyxNebula(CWE117_P09_V1_OnyxNebula.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + data);
    }
}
