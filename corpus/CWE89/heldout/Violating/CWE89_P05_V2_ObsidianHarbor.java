import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_ObsidianHarbor {
    private static boolean privateReturnsTrue() { return true; }

    private String obsidianHarborData;

    private void queryObsidianHarbor() throws SQLException {
        String data = obsidianHarborData;
        Connection obsidianHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHarbor");
        Statement obsidianHarborStatement = null;
        ResultSet obsidianHarborRows = null;
        try {
            obsidianHarborStatement = obsidianHarborConnection.createStatement();
            obsidianHarborRows = obsidianHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianHarborRows.getRow());
        } finally {
            if (obsidianHarborRows != null) {
                obsidianHarborRows.close();
            }
            if (obsidianHarborStatement != null) {
                obsidianHarborStatement.close();
            }
            obsidianHarborConnection.close();
        }
    }

    public void runObsidianHarbor() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_HARBOR_FILTER");
        } else {
            data = null;
        }
        obsidianHarborData = data;
        queryObsidianHarbor();
    }
}
