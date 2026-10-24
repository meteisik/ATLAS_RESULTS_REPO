import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronCascade {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronCascade() {
        String data;
        data = System.getenv("SAFFRON_CASCADE_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronCascadeSink()).logSaffronCascade(dataContainer);
    }
}

class CWE117_P09_V1_SaffronCascadeSink {
    public void logSaffronCascade(CWE117_P09_V1_SaffronCascade.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + data);
    }
}
