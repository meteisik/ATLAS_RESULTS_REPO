import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianHarbor {

    public void runObsidianHarbor() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianHarborSink()).queryObsidianHarbor(dataArray);
    }
}

class CWE89_P08_V1_ObsidianHarborSink {
    public void queryObsidianHarbor(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
