import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VividSignal {

    static class Container {
        public String containerOne;
    }

    public void openVividSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VIVID_SIGNAL_PATH");
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VividSignalSink()).readVividSignal(dataContainer);
    }
}

class CWE22_P09_V2_VividSignalSink {
    public void readVividSignal(CWE22_P09_V2_VividSignal.Container dataContainer) {
        String data = dataContainer.containerOne;
        String vividSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File vividSignalFile = new File(vividSignalRoot + data);
            FileInputStream vividSignalStream = null;
            InputStreamReader vividSignalStreamReader = null;
            BufferedReader vividSignalReader = null;
            if (vividSignalFile.exists() && vividSignalFile.isFile()) {
                try {
                    vividSignalStream = new FileInputStream(vividSignalFile);
                    vividSignalStreamReader = new InputStreamReader(vividSignalStream, "UTF-8");
                    vividSignalReader = new BufferedReader(vividSignalStreamReader);
                    System.out.println(vividSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VividSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividSignalReader != null) {
                            vividSignalReader.close();
                        }
                        if (vividSignalStreamReader != null) {
                            vividSignalStreamReader.close();
                        }
                        if (vividSignalStream != null) {
                            vividSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VividSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
