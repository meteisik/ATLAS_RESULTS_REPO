import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P04_V1_CrimsonLantern {

    private String locateCrimsonLantern() throws IOException {
        String data;
        data = System.getenv("CRIMSON_LANTERN_PATH");
        return data;
    }

    public void openCrimsonLantern() throws IOException {
        String data = locateCrimsonLantern();
        String crimsonLanternRoot = "/home/user/uploads/";
        File crimsonLanternFile = new File(crimsonLanternRoot + data);
        FileInputStream crimsonLanternStream = new FileInputStream(crimsonLanternFile);
        crimsonLanternStream.close();
    }
}
