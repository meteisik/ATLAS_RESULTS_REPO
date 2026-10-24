import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronSundial {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronSundialSink()).logSaffronSundial(dataContainer);
    }
}

class CWE117_P09_V1_SaffronSundialSink {
    public void logSaffronSundial(CWE117_P09_V1_SaffronSundial.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}
