import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ArcticCometSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void openArcticComet() {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ArcticCometSafeSink()).readArcticComet(dataContainer);
    }
}

class CWE22_P09_V2_ArcticCometSafeSink {
    public void readArcticComet(CWE22_P09_V2_ArcticCometSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String arcticCometRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticCometFile = new File(arcticCometRoot + data);
            FileInputStream arcticCometStream = null;
            InputStreamReader arcticCometStreamReader = null;
            BufferedReader arcticCometReader = null;
            if (arcticCometFile.exists() && arcticCometFile.isFile()) {
                try {
                    arcticCometStream = new FileInputStream(arcticCometFile);
                    arcticCometStreamReader = new InputStreamReader(arcticCometStream, "UTF-8");
                    arcticCometReader = new BufferedReader(arcticCometStreamReader);
                    System.out.println(arcticCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ArcticCometSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticCometReader != null) {
                            arcticCometReader.close();
                        }
                        if (arcticCometStreamReader != null) {
                            arcticCometStreamReader.close();
                        }
                        if (arcticCometStream != null) {
                            arcticCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ArcticCometSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
