import java.util.logging.Logger;

public class CWE117_P09_V2_AmberCascadeSafe {

    static class Container {
        public String containerOne;
    }

    public void handleAmberCascade() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AMBER_CASCADE_USER");
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberCascadeSafeSink()).logAmberCascade(dataContainer);
    }
}

class CWE117_P09_V2_AmberCascadeSafeSink {
    public void logAmberCascade(CWE117_P09_V2_AmberCascadeSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
