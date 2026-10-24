import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_VelvetGlintSafe {
    private static boolean privateTrue = true;

    public void openVelvetGlint() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_VelvetGlintSafeSink()).readVelvetGlint(dataArray);
    }
}

class CWE22_P08_V2_VelvetGlintSafeSink {
    public void readVelvetGlint(String[] dataArray) {
        String data = dataArray[2];
        String velvetGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetGlintFile = new File(velvetGlintRoot + data);
            FileInputStream velvetGlintStream = null;
            InputStreamReader velvetGlintStreamReader = null;
            BufferedReader velvetGlintReader = null;
            if (velvetGlintFile.exists() && velvetGlintFile.isFile()) {
                try {
                    velvetGlintStream = new FileInputStream(velvetGlintFile);
                    velvetGlintStreamReader = new InputStreamReader(velvetGlintStream, "UTF-8");
                    velvetGlintReader = new BufferedReader(velvetGlintStreamReader);
                    System.out.println(velvetGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V2_VelvetGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetGlintReader != null) {
                            velvetGlintReader.close();
                        }
                        if (velvetGlintStreamReader != null) {
                            velvetGlintStreamReader.close();
                        }
                        if (velvetGlintStream != null) {
                            velvetGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V2_VelvetGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
