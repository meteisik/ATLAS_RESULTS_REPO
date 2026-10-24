import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianHarborSafe {

    public void runObsidianHarbor() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_ObsidianHarborSafeSink()).queryObsidianHarbor(data);
    }
}

class CWE89_P06_V1_ObsidianHarborSafeSink {
    public void queryObsidianHarbor(String data) throws SQLException {
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
}
