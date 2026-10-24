import java.util.logging.Logger;

public class CWE117_P09_V1_RuneLotus {

    static class Container {
        public String containerOne;
    }

    public void handleRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneLotusSink()).logRuneLotus(dataContainer);
    }
}

class CWE117_P09_V1_RuneLotusSink {
    public void logRuneLotus(CWE117_P09_V1_RuneLotus.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + data);
    }
}
