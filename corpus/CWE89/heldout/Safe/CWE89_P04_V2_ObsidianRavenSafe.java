import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadObsidianRaven() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianRaven() throws SQLException {
        String data = loadObsidianRaven();
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        Statement obsidianRavenStatement = null;
        ResultSet obsidianRavenRows = null;
        try {
            obsidianRavenStatement = obsidianRavenConnection.createStatement();
            obsidianRavenRows = obsidianRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianRavenRows.getRow());
        } finally {
            if (obsidianRavenRows != null) {
                obsidianRavenRows.close();
            }
            if (obsidianRavenStatement != null) {
                obsidianRavenStatement.close();
            }
            obsidianRavenConnection.close();
        }
    }
}
