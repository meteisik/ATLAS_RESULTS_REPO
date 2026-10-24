import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_NovaGlintSafe {

    public void openNovaGlint() {
        String data;
        data = (new CWE22_P07_V1_NovaGlintSafeSource()).locateNovaGlint();
        String novaGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File novaGlintFile = new File(novaGlintRoot + data);
            FileInputStream novaGlintStream = null;
            InputStreamReader novaGlintStreamReader = null;
            BufferedReader novaGlintReader = null;
            if (novaGlintFile.exists() && novaGlintFile.isFile()) {
                try {
                    novaGlintStream = new FileInputStream(novaGlintFile);
                    novaGlintStreamReader = new InputStreamReader(novaGlintStream, "UTF-8");
                    novaGlintReader = new BufferedReader(novaGlintStreamReader);
                    System.out.println(novaGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_NovaGlintSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaGlintReader != null) {
                            novaGlintReader.close();
                        }
                        if (novaGlintStreamReader != null) {
                            novaGlintStreamReader.close();
                        }
                        if (novaGlintStream != null) {
                            novaGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_NovaGlintSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_NovaGlintSafeSource {
    public String locateNovaGlint() {
        String data;
        data = "foo";
        return data;
    }
}
