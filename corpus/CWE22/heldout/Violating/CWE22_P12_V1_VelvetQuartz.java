import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetQuartz {

    public void openVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_PATH");
        CWE22_P12_V1_VelvetQuartzBase baseObject = new CWE22_P12_V1_VelvetQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetQuartzBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetQuartzSink extends CWE22_P12_V1_VelvetQuartzBase {
    public void action(String data) {
        String velvetQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetQuartzFile = new File(velvetQuartzRoot + data);
            FileInputStream velvetQuartzStream = null;
            InputStreamReader velvetQuartzStreamReader = null;
            BufferedReader velvetQuartzReader = null;
            if (velvetQuartzFile.exists() && velvetQuartzFile.isFile()) {
                try {
                    velvetQuartzStream = new FileInputStream(velvetQuartzFile);
                    velvetQuartzStreamReader = new InputStreamReader(velvetQuartzStream, "UTF-8");
                    velvetQuartzReader = new BufferedReader(velvetQuartzStreamReader);
                    System.out.println(velvetQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VelvetQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetQuartzReader != null) {
                            velvetQuartzReader.close();
                        }
                        if (velvetQuartzStreamReader != null) {
                            velvetQuartzStreamReader.close();
                        }
                        if (velvetQuartzStream != null) {
                            velvetQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VelvetQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
