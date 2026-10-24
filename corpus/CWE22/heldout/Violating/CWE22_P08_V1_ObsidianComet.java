import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_ObsidianComet {

    public void openObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_ObsidianCometSink()).readObsidianComet(dataArray);
    }
}

class CWE22_P08_V1_ObsidianCometSink {
    public void readObsidianComet(String[] dataArray) {
        String data = dataArray[2];
        String obsidianCometRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianCometFile = new File(obsidianCometRoot + data);
            FileInputStream obsidianCometStream = null;
            InputStreamReader obsidianCometStreamReader = null;
            BufferedReader obsidianCometReader = null;
            if (obsidianCometFile.exists() && obsidianCometFile.isFile()) {
                try {
                    obsidianCometStream = new FileInputStream(obsidianCometFile);
                    obsidianCometStreamReader = new InputStreamReader(obsidianCometStream, "UTF-8");
                    obsidianCometReader = new BufferedReader(obsidianCometStreamReader);
                    System.out.println(obsidianCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_ObsidianCometSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianCometReader != null) {
                            obsidianCometReader.close();
                        }
                        if (obsidianCometStreamReader != null) {
                            obsidianCometStreamReader.close();
                        }
                        if (obsidianCometStream != null) {
                            obsidianCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_ObsidianCometSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
