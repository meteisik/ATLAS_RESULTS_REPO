import java.util.logging.Logger;

public class CWE117_P09_V1_RuneLantern {

    static class Container {
        public String containerOne;
    }

    public void handleRuneLantern() {
        String data;
        data = System.getenv("RUNE_LANTERN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneLanternSink()).logRuneLantern(dataContainer);
    }
}

class CWE117_P09_V1_RuneLanternSink {
    public void logRuneLantern(CWE117_P09_V1_RuneLantern.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeLanternLogger = Logger.getLogger("runeLantern.audit");
        runeLanternLogger.info("Login attempt for user " + data);
    }
}
