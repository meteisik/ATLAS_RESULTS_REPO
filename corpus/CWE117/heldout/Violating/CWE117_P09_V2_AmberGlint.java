import java.util.logging.Logger;

public class CWE117_P09_V2_AmberGlint {

    static class Container {
        public String containerOne;
    }

    public void handleAmberGlint() {
        String data;
        if (true) {
            data = System.getenv("AMBER_GLINT_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberGlintSink()).logAmberGlint(dataContainer);
    }
}

class CWE117_P09_V2_AmberGlintSink {
    public void logAmberGlint(CWE117_P09_V2_AmberGlint.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + data);
    }
}
