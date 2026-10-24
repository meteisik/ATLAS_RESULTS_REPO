import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_ObsidianHarborSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void queryObsidianHarbor(String data) throws SQLException {
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
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        queryObsidianHarbor(data);
    }
}
