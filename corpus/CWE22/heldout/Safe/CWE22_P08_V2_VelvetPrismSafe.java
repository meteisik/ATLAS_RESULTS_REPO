import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_VelvetPrismSafe {
    private static int privateFive = 5;

    public void openVelvetPrism() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_VelvetPrismSafeSink()).readVelvetPrism(dataArray);
    }
}

class CWE22_P08_V2_VelvetPrismSafeSink {
    public void readVelvetPrism(String[] dataArray) {
        String data = dataArray[2];
        String velvetPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetPrismFile = new File(velvetPrismRoot + data);
            FileInputStream velvetPrismStream = null;
            InputStreamReader velvetPrismStreamReader = null;
            BufferedReader velvetPrismReader = null;
            if (velvetPrismFile.exists() && velvetPrismFile.isFile()) {
                try {
                    velvetPrismStream = new FileInputStream(velvetPrismFile);
                    velvetPrismStreamReader = new InputStreamReader(velvetPrismStream, "UTF-8");
                    velvetPrismReader = new BufferedReader(velvetPrismStreamReader);
                    System.out.println(velvetPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V2_VelvetPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetPrismReader != null) {
                            velvetPrismReader.close();
                        }
                        if (velvetPrismStreamReader != null) {
                            velvetPrismStreamReader.close();
                        }
                        if (velvetPrismStream != null) {
                            velvetPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V2_VelvetPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
