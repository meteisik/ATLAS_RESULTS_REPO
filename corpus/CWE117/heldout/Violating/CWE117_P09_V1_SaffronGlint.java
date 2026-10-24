import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronGlint {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronGlint() {
        String data;
        data = System.getenv("SAFFRON_GLINT_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronGlintSink()).logSaffronGlint(dataContainer);
    }
}

class CWE117_P09_V1_SaffronGlintSink {
    public void logSaffronGlint(CWE117_P09_V1_SaffronGlint.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + data);
    }
}
