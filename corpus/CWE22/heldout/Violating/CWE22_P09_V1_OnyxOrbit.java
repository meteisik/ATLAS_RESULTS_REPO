import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_OnyxOrbit {

    static class Container {
        public String containerOne;
    }

    public void openOnyxOrbit() {
        String data;
        data = System.getenv("ONYX_ORBIT_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_OnyxOrbitSink()).readOnyxOrbit(dataContainer);
    }
}

class CWE22_P09_V1_OnyxOrbitSink {
    public void readOnyxOrbit(CWE22_P09_V1_OnyxOrbit.Container dataContainer) {
        String data = dataContainer.containerOne;
        String onyxOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxOrbitFile = new File(onyxOrbitRoot + data);
            FileInputStream onyxOrbitStream = null;
            InputStreamReader onyxOrbitStreamReader = null;
            BufferedReader onyxOrbitReader = null;
            if (onyxOrbitFile.exists() && onyxOrbitFile.isFile()) {
                try {
                    onyxOrbitStream = new FileInputStream(onyxOrbitFile);
                    onyxOrbitStreamReader = new InputStreamReader(onyxOrbitStream, "UTF-8");
                    onyxOrbitReader = new BufferedReader(onyxOrbitStreamReader);
                    System.out.println(onyxOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_OnyxOrbitSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxOrbitReader != null) {
                            onyxOrbitReader.close();
                        }
                        if (onyxOrbitStreamReader != null) {
                            onyxOrbitStreamReader.close();
                        }
                        if (onyxOrbitStream != null) {
                            onyxOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_OnyxOrbitSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
