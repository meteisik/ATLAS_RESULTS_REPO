import java.util.logging.Logger;

public class CWE117_P09_V2_VividSundial {

    static class Container {
        public String containerOne;
    }

    public void handleVividSundial() {
        String data;
        if (true) {
            data = System.getenv("VIVID_SUNDIAL_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VividSundialSink()).logVividSundial(dataContainer);
    }
}

class CWE117_P09_V2_VividSundialSink {
    public void logVividSundial(CWE117_P09_V2_VividSundial.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + data);
    }
}
