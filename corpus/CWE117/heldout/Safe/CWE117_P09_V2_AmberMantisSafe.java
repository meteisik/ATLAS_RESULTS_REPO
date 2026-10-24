import java.util.logging.Logger;

public class CWE117_P09_V2_AmberMantisSafe {

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
        (new CWE117_P09_V2_AmberMantisSafeSink()).logAmberMantis(dataContainer);
    }
}

class CWE117_P09_V2_AmberMantisSafeSink {
    public void logAmberMantis(CWE117_P09_V2_AmberMantisSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
