import java.util.logging.Logger;

public class CWE117_P09_V2_AmberSundial {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void handleAmberSundial() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_SUNDIAL_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberSundialSink()).logAmberSundial(dataContainer);
    }
}

class CWE117_P09_V2_AmberSundialSink {
    public void logAmberSundial(CWE117_P09_V2_AmberSundial.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + data);
    }
}
