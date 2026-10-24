import java.util.logging.Logger;

public class CWE117_P09_V2_AmberMantis {

    static class Container {
        public String containerOne;
    }

    public void handleAmberMantis() {
        String data;
        if (5 == 5) {
            data = System.getenv("AMBER_MANTIS_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberMantisSink()).logAmberMantis(dataContainer);
    }
}

class CWE117_P09_V2_AmberMantisSink {
    public void logAmberMantis(CWE117_P09_V2_AmberMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + data);
    }
}
