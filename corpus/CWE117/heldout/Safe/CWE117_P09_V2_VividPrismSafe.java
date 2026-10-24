import java.util.logging.Logger;

public class CWE117_P09_V2_VividPrismSafe {

    static class Container {
        public String containerOne;
    }

    public void handleVividPrism() {
        String data;
        while (true) {
            data = System.getenv("VIVID_PRISM_USER");
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VividPrismSafeSink()).logVividPrism(dataContainer);
    }
}

class CWE117_P09_V2_VividPrismSafeSink {
    public void logVividPrism(CWE117_P09_V2_VividPrismSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
