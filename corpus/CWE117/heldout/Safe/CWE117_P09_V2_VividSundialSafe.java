import java.util.logging.Logger;

public class CWE117_P09_V2_VividSundialSafe {

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
        (new CWE117_P09_V2_VividSundialSafeSink()).logVividSundial(dataContainer);
    }
}

class CWE117_P09_V2_VividSundialSafeSink {
    public void logVividSundial(CWE117_P09_V2_VividSundialSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
