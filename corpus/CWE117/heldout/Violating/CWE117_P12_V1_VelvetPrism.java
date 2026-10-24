import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetPrism {

    public void handleVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_USER");
        CWE117_P12_V1_VelvetPrismBase baseObject = new CWE117_P12_V1_VelvetPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetPrismBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetPrismSink extends CWE117_P12_V1_VelvetPrismBase {
    public void action(String data) {
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + data);
    }
}
