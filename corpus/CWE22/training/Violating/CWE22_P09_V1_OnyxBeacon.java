import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P09_V1_OnyxBeacon {

    static class Container {
        public String containerOne;
    }

    public void openOnyxBeacon() throws IOException {
        String data;
        data = System.getenv("ONYX_BEACON_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_OnyxBeaconSink()).readOnyxBeacon(dataContainer);
    }
}

class CWE22_P09_V1_OnyxBeaconSink {
    public void readOnyxBeacon(CWE22_P09_V1_OnyxBeacon.Container dataContainer) throws IOException {
        String data = dataContainer.containerOne;
        String onyxBeaconRoot = "/home/user/uploads/";
        File onyxBeaconFile = new File(onyxBeaconRoot + data);
        FileInputStream onyxBeaconStream = new FileInputStream(onyxBeaconFile);
        onyxBeaconStream.close();
    }
}
