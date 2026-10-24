import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_ObsidianHelix {
    private static boolean privateTrue = true;

    private void queryObsidianHelix(String data) throws SQLException {
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        Statement obsidianHelixStatement = null;
        ResultSet obsidianHelixRows = null;
        try {
            obsidianHelixStatement = obsidianHelixConnection.createStatement();
            obsidianHelixRows = obsidianHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianHelixRows.getRow());
        } finally {
            if (obsidianHelixRows != null) {
                obsidianHelixRows.close();
            }
            if (obsidianHelixStatement != null) {
                obsidianHelixStatement.close();
            }
            obsidianHelixConnection.close();
        }
    }

    public void runObsidianHelix() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_HELIX_FILTER");
        } else {
            data = null;
        }
        queryObsidianHelix(data);
    }
}
