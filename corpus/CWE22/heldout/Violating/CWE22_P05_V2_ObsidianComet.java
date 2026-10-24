import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_ObsidianComet {
    private String obsidianCometData;
    private static int privateFive = 5;

    private void readObsidianComet() {
        String data = obsidianCometData;
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
                    Logger.getLogger("CWE22_P05_V2_ObsidianComet").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P05_V2_ObsidianComet").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openObsidianComet() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_COMET_PATH");
        } else {
            data = null;
        }
        obsidianCometData = data;
        readObsidianComet();
    }
}
