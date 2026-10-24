import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianNebulaSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadObsidianNebula() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianNebula() throws SQLException {
        String data = loadObsidianNebula();
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        Statement obsidianNebulaStatement = null;
        ResultSet obsidianNebulaRows = null;
        try {
            obsidianNebulaStatement = obsidianNebulaConnection.createStatement();
            obsidianNebulaRows = obsidianNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianNebulaRows.getRow());
        } finally {
            if (obsidianNebulaRows != null) {
                obsidianNebulaRows.close();
            }
            if (obsidianNebulaStatement != null) {
                obsidianNebulaStatement.close();
            }
            obsidianNebulaConnection.close();
        }
    }
}
