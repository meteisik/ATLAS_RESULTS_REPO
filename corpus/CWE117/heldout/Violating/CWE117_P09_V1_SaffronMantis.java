import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronMantis {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronMantisSink()).logSaffronMantis(dataContainer);
    }
}

class CWE117_P09_V1_SaffronMantisSink {
    public void logSaffronMantis(CWE117_P09_V1_SaffronMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + data);
    }
}
