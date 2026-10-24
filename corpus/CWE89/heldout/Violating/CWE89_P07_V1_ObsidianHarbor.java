import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianHarbor {

    public void runObsidianHarbor() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianHarborSource()).loadObsidianHarbor();
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

class CWE89_P07_V1_ObsidianHarborSource {
    public String loadObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_FILTER");
        return data;
    }
}
