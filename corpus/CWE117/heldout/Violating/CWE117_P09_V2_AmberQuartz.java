import java.util.logging.Logger;

public class CWE117_P09_V2_AmberQuartz {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void handleAmberQuartz() {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_QUARTZ_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberQuartzSink()).logAmberQuartz(dataContainer);
    }
}

class CWE117_P09_V2_AmberQuartzSink {
    public void logAmberQuartz(CWE117_P09_V2_AmberQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + data);
    }
}
