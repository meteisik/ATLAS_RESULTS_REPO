import java.util.logging.Logger;

public class CWE117_P09_V2_VividGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void handleVividGlint() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("VIVID_GLINT_USER");
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VividGlintSafeSink()).logVividGlint(dataContainer);
    }
}

class CWE117_P09_V2_VividGlintSafeSink {
    public void logVividGlint(CWE117_P09_V2_VividGlintSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
