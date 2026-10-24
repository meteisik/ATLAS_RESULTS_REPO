import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VividSundial {

    static class Container {
        public String containerOne;
    }

    public void openVividSundial() {
        String data;
        if (true) {
            data = System.getenv("VIVID_SUNDIAL_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VividSundialSink()).readVividSundial(dataContainer);
    }
}

class CWE22_P09_V2_VividSundialSink {
    public void readVividSundial(CWE22_P09_V2_VividSundial.Container dataContainer) {
        String data = dataContainer.containerOne;
        String vividSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File vividSundialFile = new File(vividSundialRoot + data);
            FileInputStream vividSundialStream = null;
            InputStreamReader vividSundialStreamReader = null;
            BufferedReader vividSundialReader = null;
            if (vividSundialFile.exists() && vividSundialFile.isFile()) {
                try {
                    vividSundialStream = new FileInputStream(vividSundialFile);
                    vividSundialStreamReader = new InputStreamReader(vividSundialStream, "UTF-8");
                    vividSundialReader = new BufferedReader(vividSundialStreamReader);
                    System.out.println(vividSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VividSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividSundialReader != null) {
                            vividSundialReader.close();
                        }
                        if (vividSundialStreamReader != null) {
                            vividSundialStreamReader.close();
                        }
                        if (vividSundialStream != null) {
                            vividSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VividSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
