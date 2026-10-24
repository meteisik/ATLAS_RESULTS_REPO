import java.util.logging.Logger;

public class CWE117_P09_V2_AmberCascade {

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
        (new CWE117_P09_V2_AmberCascadeSink()).logAmberCascade(dataContainer);
    }
}

class CWE117_P09_V2_AmberCascadeSink {
    public void logAmberCascade(CWE117_P09_V2_AmberCascade.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + data);
    }
}
