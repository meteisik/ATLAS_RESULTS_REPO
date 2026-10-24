import java.util.logging.Logger;

public class CWE117_P08_V1_NovaPrism {

    public void handleNovaPrism() {
        String data;
        data = System.getenv("NOVA_PRISM_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_NovaPrismSink()).logNovaPrism(dataArray);
    }
}

class CWE117_P08_V1_NovaPrismSink {
    public void logNovaPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
    }
}
