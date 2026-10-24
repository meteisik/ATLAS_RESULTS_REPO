import java.util.logging.Logger;

public class CWE117_P09_V2_VividPrism {

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
        (new CWE117_P09_V2_VividPrismSink()).logVividPrism(dataContainer);
    }
}

class CWE117_P09_V2_VividPrismSink {
    public void logVividPrism(CWE117_P09_V2_VividPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + data);
    }
}
