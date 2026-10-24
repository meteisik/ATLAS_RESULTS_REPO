import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_OnyxComet {

    static class Container {
        public String containerOne;
    }

    public void openOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_OnyxCometSink()).readOnyxComet(dataContainer);
    }
}

class CWE22_P09_V1_OnyxCometSink {
    public void readOnyxComet(CWE22_P09_V1_OnyxComet.Container dataContainer) {
        String data = dataContainer.containerOne;
        String onyxCometRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxCometFile = new File(onyxCometRoot + data);
            FileInputStream onyxCometStream = null;
            InputStreamReader onyxCometStreamReader = null;
            BufferedReader onyxCometReader = null;
            if (onyxCometFile.exists() && onyxCometFile.isFile()) {
                try {
                    onyxCometStream = new FileInputStream(onyxCometFile);
                    onyxCometStreamReader = new InputStreamReader(onyxCometStream, "UTF-8");
                    onyxCometReader = new BufferedReader(onyxCometStreamReader);
                    System.out.println(onyxCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_OnyxCometSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxCometReader != null) {
                            onyxCometReader.close();
                        }
                        if (onyxCometStreamReader != null) {
                            onyxCometStreamReader.close();
                        }
                        if (onyxCometStream != null) {
                            onyxCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_OnyxCometSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
